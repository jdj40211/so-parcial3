/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mmguard.h: definiciones internas del módulo mmguard.
 *
 * Idea general (resumen; el detalle está en docs/INFORME.md):
 *
 *   - Una "bóveda" (vault) global guarda MMG_PAGES páginas CIFRADAS (AES-256-CTR)
 *     y autenticadas (HMAC-SHA256, cifrar y luego autenticar).
 *   - Cada open() de /dev/mmguard crea una "sesión" (mmg_session). Los textos en
 *     claro solo existen en páginas PRIVADAS de la sesión, creadas bajo demanda en
 *     el manejador de fallos, y se destruyen (con memzero) al cerrar la sesión.
 *   - mmap() valida una ACL por UID y endurece la VMA (flags).
 *   - Todo evento relevante se audita (log del kernel + anillo en /proc/mmguard).
 */
#ifndef MMGUARD_H
#define MMGUARD_H

/* pr_fmt debe definirse antes de incluir <linux/printk.h> (lo hace cada .c primero). */
#ifndef pr_fmt
#define pr_fmt(fmt) "mmguard: " fmt
#endif

#include <linux/atomic.h>
#include <linux/bitmap.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/fs.h>
#include <linux/mm_types.h>
#include <linux/mutex.h>
#include <linux/types.h>

#include "mmguard_uapi.h"

#define MMG_PAGES        MMGUARD_VAULT_PAGES
#define MMG_MAC_LEN      32
#define MMG_DIGEST_LEN   32
#define MMG_KEY_LEN      32
#define MMG_MAX_UIDS     16

/* ------------------------------------------------------------------ */
/* Parámetros del módulo (definidos en mmguard_main.c)                 */
/* ------------------------------------------------------------------ */
extern bool mmg_verify_on_fault;    /* recalcula SHA-256 de la página en cada fallo */
extern bool mmg_use_vm_io;          /* marca la VMA con VM_IO (bloquea GUP remoto) */
extern bool mmg_allow_debug;        /* habilita los ioctl de depuración/ataque simulado */
extern char *mmg_watch_path;        /* ruta vigilada por el kprobe de auditoría */

/* ------------------------------------------------------------------ */
/* Contadores de auditoría                                              */
/* ------------------------------------------------------------------ */
enum mmg_ctr {
	MMG_C_MMAP_OK,
	MMG_C_MMAP_DENIED,
	MMG_C_FAULT,
	MMG_C_FAULT_DECRYPT,
	MMG_C_FAULT_REFRESH,
	MMG_C_MKWRITE,
	MMG_C_SEAL,
	MMG_C_SEAL_PAGES,
	MMG_C_INTEG_FAIL,
	MMG_C_HEALED,
	MMG_C_REMOTE_DENIED,
	MMG_C_WRITE_DENIED,
	MMG_C_PROBE_MMAP,
	MMG_C_MAX
};

/* Tipos de evento del anillo de auditoría. */
enum mmg_ev {
	MMG_EV_OPEN,
	MMG_EV_MMAP,
	MMG_EV_DENY,
	MMG_EV_FAULT,
	MMG_EV_MKWRITE,
	MMG_EV_SEAL,
	MMG_EV_INTEGRITY,
	MMG_EV_PROBE,
	MMG_EV_ADMIN,
	MMG_EV_CLOSE,
};

/* mmguard_audit.c */
int  mmg_audit_init(void);
void mmg_audit_exit(void);
void mmg_count(enum mmg_ctr c);
u64  mmg_counter(enum mmg_ctr c);
void mmg_log(enum mmg_ev type, const char *fmt, ...) __printf(2, 3);

/* ------------------------------------------------------------------ */
/* Bóveda cifrada (mmguard_vault.c)                                     */
/* ------------------------------------------------------------------ */
int  mmg_vault_init(void);
void mmg_vault_exit(void);
/* Descifra la página idx a dst (4 KiB). Verifica el MAC antes. -EBADMSG si fue alterada. */
int  mmg_vault_read_page(unsigned int idx, void *dst, u64 *nonce_out);
/* Cifra src (4 KiB) en la página idx con un nonce nuevo y recalcula el MAC. */
int  mmg_vault_write_page(unsigned int idx, const void *src);
/* Lectura-modificación-escritura de un rango de bytes (carga administrativa). */
int  mmg_vault_load(u32 offset, const u8 *data, u32 len);
/* Verifica el MAC de todas las páginas; devuelve cuántas están corruptas. */
int  mmg_vault_verify_all(void);
u64  mmg_vault_nonce(unsigned int idx);
int  mmg_digest(const void *data, size_t len, u8 out[MMG_DIGEST_LEN]);
/* Depuración: simulan una corrupción del texto cifrado, copian texto cifrado. */
int  mmg_vault_dbg_tamper(unsigned int idx);
int  mmg_vault_dbg_dump(struct mmguard_dump *d);

/* ------------------------------------------------------------------ */
/* ACL por UID (mmguard_main.c)                                         */
/* ------------------------------------------------------------------ */
u32  mmg_policy_lookup(kuid_t uid);

/* ------------------------------------------------------------------ */
/* Sesiones y VMA (mmguard_vm.c)                                        */
/* ------------------------------------------------------------------ */
struct mmg_session {
	struct kref   ref;               /* file + una referencia por VMA */
	struct mutex  lock;              /* protege todo lo de abajo */
	kuid_t        owner;             /* euid que hizo open(): el fd no sirve a otro UID */
	struct page  *pt[MMG_PAGES];     /* páginas en claro, privadas de la sesión */
	u8            digest[MMG_PAGES][MMG_DIGEST_LEN]; /* SHA-256 esperado del texto en claro */
	u64           seen_nonce[MMG_PAGES];             /* versión de la bóveda que desciframos */
	DECLARE_BITMAP(dirty, MMG_PAGES);                /* páginas escritas y no selladas */
	u32           perms;             /* permisos con los que se hizo el último mmap */
	int           nvmas;
	bool          writer_vma;        /* hubo/hay una VMA con VM_WRITE */
	struct address_space *mapping;   /* address_space del inodo de /dev/mmguard */
	struct list_head retired;        /* páginas en claro reemplazadas pero aún mapeadas (ver retire_page) */
};

struct mmg_session *mmg_session_create(struct file *filp);
void mmg_session_get(struct mmg_session *s);
void mmg_session_put(struct mmg_session *s);
int  mmg_do_mmap(struct file *filp, struct vm_area_struct *vma);
/* Re-cifra las páginas sucias de la sesión. Devuelve cuántas selló o <0. */
int  mmg_session_seal(struct mmg_session *s);
int  mmg_session_dbg_corrupt(struct mmg_session *s, unsigned int idx);

/* ------------------------------------------------------------------ */
/* kprobe de auditoría sobre security_mmap_file (mmguard_kprobe.c)     */
/* ------------------------------------------------------------------ */
int  mmg_kprobe_init(void);
void mmg_kprobe_exit(void);

#endif /* MMGUARD_H */
