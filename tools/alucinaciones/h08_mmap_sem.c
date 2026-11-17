// SPDX-License-Identifier: GPL-2.0
/* Candidato típico (kernels < 5.8): mm->mmap_sem. */
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/sched.h>
MODULE_LICENSE("GPL");
static int __init m_init(void)
{
	down_read(&current->mm->mmap_sem);
	up_read(&current->mm->mmap_sem);
	return 0;
}
static void __exit m_exit(void) {}
module_init(m_init); module_exit(m_exit);
