// SPDX-License-Identifier: GPL-2.0
/* Candidato inseguro: apagar el bit WP de CR0 para escribir en memoria de solo lectura (x86). */
#include <linux/module.h>
MODULE_LICENSE("GPL");
static int __init m_init(void)
{
	unsigned long cr0 = read_cr0();
	write_cr0(cr0 & ~0x10000UL);     /* bit 16 = WP; sin control de concurrencia ni de otros núcleos */
	return 0;
}
static void __exit m_exit(void) {}
module_init(m_init); module_exit(m_exit);
