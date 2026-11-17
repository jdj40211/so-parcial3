// SPDX-License-Identifier: GPL-2.0
/* Candidato típico (kernels < 5.10): set_fs(KERNEL_DS) para pasar punteros de kernel a syscalls. */
#include <linux/module.h>
#include <linux/uaccess.h>
MODULE_LICENSE("GPL");
static int __init m_init(void)
{
	mm_segment_t old = get_fs();
	set_fs(KERNEL_DS);
	set_fs(old);
	return 0;
}
static void __exit m_exit(void) {}
module_init(m_init); module_exit(m_exit);
