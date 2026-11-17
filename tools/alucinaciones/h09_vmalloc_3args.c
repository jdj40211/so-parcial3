// SPDX-License-Identifier: GPL-2.0
/* Candidato típico (kernels < 5.8): __vmalloc(size, gfp, prot). */
#include <linux/module.h>
#include <linux/vmalloc.h>
MODULE_LICENSE("GPL");
static int __init m_init(void)
{
	void *p = __vmalloc(4096, GFP_KERNEL, PAGE_KERNEL);
	vfree(p);
	return 0;
}
static void __exit m_exit(void) {}
module_init(m_init); module_exit(m_exit);
