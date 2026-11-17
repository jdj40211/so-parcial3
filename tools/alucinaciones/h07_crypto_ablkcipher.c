// SPDX-License-Identifier: GPL-2.0
/* Candidato típico: API asíncrona antigua de cifrado por bloques (eliminada en 4.x/5.x). */
#include <linux/module.h>
#include <linux/crypto.h>
MODULE_LICENSE("GPL");
static struct crypto_ablkcipher *tfm;
static int __init m_init(void)
{
	tfm = crypto_alloc_ablkcipher("ctr(aes)", 0, 0);
	return IS_ERR(tfm) ? PTR_ERR(tfm) : 0;
}
static void __exit m_exit(void) {}
module_init(m_init); module_exit(m_exit);
