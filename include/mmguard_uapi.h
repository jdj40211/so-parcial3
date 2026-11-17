/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mmguard_uapi.h: interfaz entre el módulo de kernel y el espacio de usuario.
 *
 * Este archivo lo incluyen tanto el módulo (kernel/) como los programas de
 * usuario (user/), de modo que las estructuras y los números de ioctl nunca
 * pueden divergir.
 */
#ifndef MMGUARD_UAPI_H
#define MMGUARD_UAPI_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define MMGUARD_DEV_NAME      "mmguard"
#define MMGUARD_DEV_PATH      "/dev/mmguard"
#define MMGUARD_VAULT_PAGES   16            /* 16 páginas = 64 KiB (con página de 4 KiB) */
#define MMGUARD_UAPI_PAGE     4096          /* tamaño de página que asume la UAPI */

/* Permisos de la lista de control de acceso (ACL) por UID. */
#define MMGUARD_PERM_READ     0x1
#define MMGUARD_PERM_WRITE    0x2           /* implica poder sellar (re-cifrar) cambios */

struct mmguard_uid_ent {
	__u32 uid;
	__u32 perms;                        /* MMGUARD_PERM_* */
};

/* Carga de contenido a la bóveda (solo administrador, CAP_SYS_ADMIN). */
struct mmguard_load {
	__u32 offset;                       /* byte dentro de la bóveda */
	__u32 len;
	__u64 ptr;                          /* puntero de usuario con los datos */
};

/* Contadores de auditoría (también visibles en /proc/mmguard). */
struct mmguard_stats {
	__u64 mmap_ok;
	__u64 mmap_denied;
	__u64 faults;
	__u64 faults_decrypt;               /* fallos que provocaron un descifrado */
	__u64 faults_refresh;               /* re-descifrado por versión nueva en la bóveda */
	__u64 page_mkwrite;
	__u64 seals;
	__u64 seal_pages;
	__u64 integrity_fail;
	__u64 healed;
	__u64 remote_denied;
	__u64 write_denied;
	__u64 probe_mmap;                   /* mmaps vistos por el kprobe (ruta vigilada) */
};

/* Utilidades de depuración (solo con el parámetro allow_debug=1 y CAP_SYS_ADMIN). */
struct mmguard_dump {
	__u32 page;                         /* in: índice de página de la bóveda */
	__u32 len;                          /* in: bytes a copiar (<= 4096) */
	__u64 ptr;                          /* in: búfer de usuario destino */
	__u64 kaddr;                        /* out: dirección virtual del kernel del texto cifrado */
	__u64 nonce;                        /* out: nonce (contador de sellado) de la página */
};

#define MMGUARD_IOC_MAGIC     'M'
#define MMGUARD_IOC_ADD_UID   _IOW(MMGUARD_IOC_MAGIC, 1, struct mmguard_uid_ent)
#define MMGUARD_IOC_DEL_UID   _IOW(MMGUARD_IOC_MAGIC, 2, __u32)
#define MMGUARD_IOC_LOAD      _IOW(MMGUARD_IOC_MAGIC, 3, struct mmguard_load)
#define MMGUARD_IOC_SEAL      _IO(MMGUARD_IOC_MAGIC, 4)
#define MMGUARD_IOC_VERIFY    _IOR(MMGUARD_IOC_MAGIC, 5, __u32)   /* devuelve # de páginas corruptas */
#define MMGUARD_IOC_STATS     _IOR(MMGUARD_IOC_MAGIC, 6, struct mmguard_stats)
#define MMGUARD_IOC_DBG_TAMPER_VAULT   _IOW(MMGUARD_IOC_MAGIC, 7, __u32)  /* voltea 1 bit del cifrado */
#define MMGUARD_IOC_DBG_CORRUPT_PAGE   _IOW(MMGUARD_IOC_MAGIC, 8, __u32)  /* voltea 1 byte de la página en claro de la sesión */
#define MMGUARD_IOC_DBG_DUMP_CT        _IOWR(MMGUARD_IOC_MAGIC, 9, struct mmguard_dump)

#endif /* MMGUARD_UAPI_H */
