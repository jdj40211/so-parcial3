// SPDX-License-Identifier: GPL-2.0
/*
 * mmguard_audit.c: auditoría. Cada evento relevante (mmap, fallo de página,
 * rechazo, cambio sospechoso) se registra en:
 *   1. el log del kernel (dmesg) con PID, TGID, UID y nombre del comando;
 *   2. un anillo en memoria con los últimos eventos, visible en /proc/mmguard;
 *   3. contadores atómicos, visibles en /proc/mmguard y por ioctl(STATS).
 *
 * Los fallos de página, las notificaciones de escritura y los sellados se cuentan siempre,
 * pero su línea de dmesg se limita con ratelimit: un ataque de carrera genera decenas de miles de fallos por segundo
 * y saturaría el búfer de printk. El anillo y los contadores no pierden nada.
 */
#include "mmguard.h"

#include <linux/cred.h>
#include <linux/jiffies.h>
#include <linux/proc_fs.h>
#include <linux/ratelimit.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/stdarg.h>
#include <linux/string.h>

#define MMG_RING_SIZE   128
#define MMG_MSG_LEN     176

static atomic64_t counters[MMG_C_MAX];

static const char * const counter_names[MMG_C_MAX] = {
	[MMG_C_MMAP_OK]        = "mmap_ok",
	[MMG_C_MMAP_DENIED]    = "mmap_denegados",
	[MMG_C_FAULT]          = "fallos_de_pagina",
	[MMG_C_FAULT_DECRYPT]  = "fallos_con_descifrado",
	[MMG_C_FAULT_REFRESH]  = "fallos_con_refresco",
	[MMG_C_MKWRITE]        = "page_mkwrite",
	[MMG_C_SEAL]           = "sellados",
	[MMG_C_SEAL_PAGES]     = "paginas_selladas",
	[MMG_C_INTEG_FAIL]     = "violaciones_integridad",
	[MMG_C_HEALED]         = "paginas_reparadas",
	[MMG_C_REMOTE_DENIED]  = "accesos_remotos_denegados",
	[MMG_C_WRITE_DENIED]   = "escrituras_denegadas",
	[MMG_C_PROBE_MMAP]     = "mmap_vistos_por_kprobe",
};

static const char * const ev_names[] = {
	[MMG_EV_OPEN]      = "OPEN",
	[MMG_EV_MMAP]      = "MMAP",
	[MMG_EV_DENY]      = "DENIEGA",
	[MMG_EV_FAULT]     = "FALLO",
	[MMG_EV_MKWRITE]   = "ESCRIBE",
	[MMG_EV_SEAL]      = "SELLA",
	[MMG_EV_INTEGRITY] = "INTEGRIDAD",
	[MMG_EV_PROBE]     = "KPROBE",
	[MMG_EV_ADMIN]     = "ADMIN",
	[MMG_EV_CLOSE]     = "CIERRA",
};

struct mmg_event {
	u64   seq;
	u64   ts_ms;
	char  msg[MMG_MSG_LEN];
};

static struct mmg_event ring[MMG_RING_SIZE];
static u64 ring_seq;
static DEFINE_SPINLOCK(ring_lock);

/* Máximo 20 líneas de dmesg por fallo de página cada 5 s; el resto va solo al anillo. */
static DEFINE_RATELIMIT_STATE(fault_rs, 5 * HZ, 20);

static struct proc_dir_entry *proc_entry;

void mmg_count(enum mmg_ctr c)
{
	atomic64_inc(&counters[c]);
}

u64 mmg_counter(enum mmg_ctr c)
{
	return atomic64_read(&counters[c]);
}

/**
 * mmg_log - registra un evento de auditoría
 * @type: categoría del evento
 * @fmt:  detalle (printf)
 *
 * Puede llamarse desde contexto de proceso o desde un kprobe (no duerme).
 */
void mmg_log(enum mmg_ev type, const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;
	char body[MMG_MSG_LEN - 64];
	char line[MMG_MSG_LEN];
	unsigned long flags;
	bool to_dmesg = true;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	scnprintf(body, sizeof(body), "%pV", &vaf);
	va_end(args);

	scnprintf(line, sizeof(line), "%s pid=%d tgid=%d uid=%u comm=%s %s",
		  ev_names[type], current->pid, current->tgid,
		  from_kuid(&init_user_ns, current_euid()), current->comm, body);

	spin_lock_irqsave(&ring_lock, flags);
	ring[ring_seq % MMG_RING_SIZE].seq = ring_seq;
	ring[ring_seq % MMG_RING_SIZE].ts_ms = jiffies_to_msecs(jiffies);
	strscpy(ring[ring_seq % MMG_RING_SIZE].msg, line, MMG_MSG_LEN);
	ring_seq++;
	spin_unlock_irqrestore(&ring_lock, flags);

	if (type == MMG_EV_FAULT || type == MMG_EV_MKWRITE || type == MMG_EV_SEAL)
		to_dmesg = __ratelimit(&fault_rs);

	if (!to_dmesg)
		return;

	if (type == MMG_EV_DENY || type == MMG_EV_INTEGRITY)
		pr_warn("%s\n", line);
	else
		pr_info("%s\n", line);
}

static int mmg_proc_show(struct seq_file *m, void *v)
{
	unsigned long flags;
	u64 first, i;
	int c;

	seq_puts(m, "# mmguard: auditoría de mapeos protegidos\n");
	seq_printf(m, "parametros: verify_on_fault=%d use_vm_io=%d allow_debug=%d watch_path=\"%s\"\n",
		   mmg_verify_on_fault, mmg_use_vm_io, mmg_allow_debug,
		   mmg_watch_path ? mmg_watch_path : "");
	seq_printf(m, "boveda: %d paginas de %lu bytes, AES-256-CTR + HMAC-SHA256\n",
		   MMG_PAGES, PAGE_SIZE);
	seq_puts(m, "\n[contadores]\n");
	for (c = 0; c < MMG_C_MAX; c++)
		seq_printf(m, "%-28s %llu\n", counter_names[c],
			   (unsigned long long)mmg_counter(c));

	seq_puts(m, "\n[ultimos eventos]\n");
	spin_lock_irqsave(&ring_lock, flags);
	first = ring_seq > MMG_RING_SIZE ? ring_seq - MMG_RING_SIZE : 0;
	for (i = first; i < ring_seq; i++) {
		struct mmg_event *e = &ring[i % MMG_RING_SIZE];

		seq_printf(m, "#%llu t=%llums %s\n", (unsigned long long)e->seq,
			   (unsigned long long)e->ts_ms, e->msg);
	}
	spin_unlock_irqrestore(&ring_lock, flags);
	return 0;
}

int mmg_audit_init(void)
{
	proc_entry = proc_create_single("mmguard", 0444, NULL, mmg_proc_show);
	if (!proc_entry)
		return -ENOMEM;
	return 0;
}

void mmg_audit_exit(void)
{
	proc_remove(proc_entry);
}
