// SPDX-License-Identifier: GPL-2.0
/* Candidato típico (kernels < 6.5): get_user_pages() con el parámetro vmas. */
#include <linux/module.h>
#include <linux/mm.h>
MODULE_LICENSE("GPL");
static int __init m_init(void)
{
	struct page *pg;
	struct vm_area_struct *vmas[1];
	long n = get_user_pages(0x1000, 1, FOLL_WRITE, &pg, vmas);   /* 5 argumentos: ya no existe */
	return n < 0;
}
static void __exit m_exit(void) {}
module_init(m_init); module_exit(m_exit);
