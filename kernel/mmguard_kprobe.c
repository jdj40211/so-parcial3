// SPDX-License-Identifier: GPL-2.0
/*
 * mmguard_kprobe.c: auditoría opcional con un kprobe sobre security_mmap_file().
 *
 * security_mmap_file() es el punto por donde pasa todo mmap() de archivo (es donde
 * un LSM como SELinux/AppArmor engancha su hook file_mmap). El kprobe SOLO OBSERVA:
 * lee los argumentos, compara la ruta del archivo con el parámetro watch_path y deja
 * constancia en el log. No modifica registros, no cambia el valor de retorno y no
 * toca la tabla de llamadas al sistema.
 *
 * Por qué no modificar sys_call_table: (1) desde Linux 5.7 kallsyms_lookup_name()
 * no está exportada y el símbolo sys_call_table tampoco; (2) la tabla vive en una
 * sección de solo lectura tras el arranque; (3) la receta clásica (apagar WP en CR0)
 * es solo x86, es una operación privilegiada que desde 5.3 el kernel "fija" para
 * impedirla, y deja una ventana en la que otro núcleo escribe donde no debe;
 * (4) romper una syscall de otro afecta a TODO el sistema, y (5) no vería los mmap
 * hechos por io_uring ni por rutas internas. Un kprobe es la interfaz soportada.
 */
#include "mmguard.h"

#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/mman.h>
#include <linux/path.h>
#include <linux/ptrace.h>
#include <linux/string.h>

static struct kprobe kp = {
	.symbol_name = "security_mmap_file",
};
static bool kp_registered;

static int mmg_kp_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct file *file;
	unsigned long prot;
	char buf[192], *name;

	if (!mmg_watch_path || !mmg_watch_path[0])
		return 0;

	/* int security_mmap_file(struct file *file, unsigned long prot, unsigned long flags) */
#if defined(CONFIG_ARM64)
	file = (struct file *)regs->regs[0];
	prot = regs->regs[1];
#elif defined(CONFIG_X86_64)
	file = (struct file *)regs->di;
	prot = regs->si;
#else
	return 0;
#endif
	if (!file)               /* mmap anónimo */
		return 0;

	/* d_path no duerme (usa RCU y un seqlock), por lo que es válido en un kprobe. */
	name = d_path(&file->f_path, buf, sizeof(buf));
	if (IS_ERR(name))
		return 0;
	if (strncmp(name, mmg_watch_path, strlen(mmg_watch_path)))
		return 0;

	mmg_count(MMG_C_PROBE_MMAP);
	mmg_log(MMG_EV_PROBE, "mmap de archivo vigilado %s prot=%c%c%c", name,
		(prot & PROT_READ) ? 'r' : '-', (prot & PROT_WRITE) ? 'w' : '-',
		(prot & PROT_EXEC) ? 'x' : '-');
	return 0;
}

int mmg_kprobe_init(void)
{
	int ret;

	if (!mmg_watch_path || !mmg_watch_path[0])
		return 0;                 /* sin ruta vigilada no se instala el kprobe */
	kp.pre_handler = mmg_kp_pre;
	ret = register_kprobe(&kp);
	if (!ret)
		kp_registered = true;
	return ret;
}

void mmg_kprobe_exit(void)
{
	if (kp_registered)
		unregister_kprobe(&kp);
}
