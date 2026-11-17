// SPDX-License-Identifier: GPL-2.0
/* Candidato típico (kernels < 6.4): class_create(THIS_MODULE, "nombre"). */
#include <linux/module.h>
#include <linux/device.h>
MODULE_LICENSE("GPL");
static struct class *c;
static int __init m_init(void)
{
	c = class_create(THIS_MODULE, "mmguard");
	return IS_ERR(c) ? PTR_ERR(c) : 0;
}
static void __exit m_exit(void) { class_destroy(c); }
module_init(m_init); module_exit(m_exit);
