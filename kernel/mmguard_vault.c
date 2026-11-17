// SPDX-License-Identifier: GPL-2.0
/*
 * mmguard_vault.c: la bóveda. Guarda las páginas CIFRADAS y las autentica.
 *
 * Cifrado:  AES-256 en modo CTR mediante la API del kernel (crypto_skcipher).
 *           IV = nonce(64 bits, big endian) || contador(64 bits).  El nonce sale
 *           de un contador global que aumenta con CADA cifrado de CADA página,
 *           así nunca se reutiliza el par (clave, flujo de claves). Reutilizarlo
 *           con CTR permitiría recuperar el XOR de dos textos en claro.
 *
 * Integridad: HMAC-SHA256 sobre (índice || nonce || texto cifrado), clave distinta
 *           de la de cifrado. Es el esquema "cifrar y luego autenticar". El MAC se
 *           verifica ANTES de descifrar, de modo que una página alterada en la
 *           memoria del kernel jamás llega a mostrarse como válida.
 *
 * Las claves se generan al cargar el módulo con get_random_bytes() y solo viven
 * en la memoria del kernel (se borran con memzero_explicit al descargar).
 */
#include "mmguard.h"

#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <crypto/utils.h>
#include <linux/crypto.h>
#include <linux/gfp.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/random.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/string.h>

struct mmg_vpage {
	struct page *ct;                 /* texto cifrado (4 KiB) */
	u64          nonce;
	u8           mac[MMG_MAC_LEN];
};

static struct {
	struct mutex          lock;
	struct mmg_vpage      pg[MMG_PAGES];
	struct crypto_skcipher *cipher;
	struct crypto_shash   *hmac;
	struct crypto_shash   *sha;
	u8                    enc_key[MMG_KEY_LEN];
	u8                    mac_key[MMG_KEY_LEN];
	u64                   nonce_ctr;
} V;

/* ----------------------------- primitivas ------------------------------ */

/* SHA-256 de un búfer (para el resumen de las páginas en claro de la sesión). */
int mmg_digest(const void *data, size_t len, u8 out[MMG_DIGEST_LEN])
{
	SHASH_DESC_ON_STACK(desc, V.sha);

	desc->tfm = V.sha;
	return crypto_shash_digest(desc, data, len, out);
}

/* MAC = HMAC-SHA256(idx || nonce || ct). */
static int vault_mac(unsigned int idx, u64 nonce, const void *ct, u8 out[MMG_MAC_LEN])
{
	SHASH_DESC_ON_STACK(desc, V.hmac);
	__le64 hdr[2];
	int ret;

	hdr[0] = cpu_to_le64(idx);
	hdr[1] = cpu_to_le64(nonce);
	desc->tfm = V.hmac;
	ret = crypto_shash_init(desc);
	if (!ret)
		ret = crypto_shash_update(desc, (const u8 *)hdr, sizeof(hdr));
	if (!ret)
		ret = crypto_shash_update(desc, ct, PAGE_SIZE);
	if (!ret)
		ret = crypto_shash_final(desc, out);
	return ret;
}

/* AES-256-CTR sobre una página completa (el mismo cálculo cifra y descifra). */
static int vault_crypt(u64 nonce, const void *src, void *dst)
{
	struct skcipher_request *req;
	struct scatterlist sg_src, sg_dst;
	DECLARE_CRYPTO_WAIT(wait);
	__be64 iv[2];
	int ret;

	req = skcipher_request_alloc(V.cipher, GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	iv[0] = cpu_to_be64(nonce);
	iv[1] = 0;
	/* src y dst son memoria del mapa directo del kernel (page_address): válido para sg. */
	sg_init_one(&sg_src, src, PAGE_SIZE);
	sg_init_one(&sg_dst, dst, PAGE_SIZE);
	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
				      crypto_req_done, &wait);
	skcipher_request_set_crypt(req, &sg_src, &sg_dst, PAGE_SIZE, (u8 *)iv);
	ret = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
	skcipher_request_free(req);
	return ret;
}

/* Cifra src (claro) dentro de pg[idx]. Requiere V.lock tomado. */
static int vault_seal_locked(unsigned int idx, const void *src)
{
	struct mmg_vpage *vp = &V.pg[idx];
	u64 nonce = ++V.nonce_ctr;
	void *ct = page_address(vp->ct);
	u8 mac[MMG_MAC_LEN];
	int ret;

	ret = vault_crypt(nonce, src, ct);
	if (ret)
		return ret;
	ret = vault_mac(idx, nonce, ct, mac);
	if (ret)
		return ret;
	vp->nonce = nonce;
	memcpy(vp->mac, mac, MMG_MAC_LEN);
	return 0;
}

/* Verifica el MAC de pg[idx]. Requiere V.lock tomado. */
static int vault_check_locked(unsigned int idx)
{
	struct mmg_vpage *vp = &V.pg[idx];
	u8 mac[MMG_MAC_LEN];
	int ret;

	ret = vault_mac(idx, vp->nonce, page_address(vp->ct), mac);
	if (ret)
		return ret;
	return crypto_memneq(mac, vp->mac, MMG_MAC_LEN) ? -EBADMSG : 0;
}

/* ------------------------------ API pública ---------------------------- */

int mmg_vault_read_page(unsigned int idx, void *dst, u64 *nonce_out)
{
	int ret;

	if (idx >= MMG_PAGES)
		return -EINVAL;
	mutex_lock(&V.lock);
	ret = vault_check_locked(idx);          /* 1) autenticar */
	if (!ret) {
		ret = vault_crypt(V.pg[idx].nonce, page_address(V.pg[idx].ct), dst); /* 2) descifrar */
		if (nonce_out)
			*nonce_out = V.pg[idx].nonce;
	}
	mutex_unlock(&V.lock);
	if (ret == -EBADMSG)
		mmg_count(MMG_C_INTEG_FAIL);
	return ret;
}

int mmg_vault_write_page(unsigned int idx, const void *src)
{
	int ret;

	if (idx >= MMG_PAGES)
		return -EINVAL;
	mutex_lock(&V.lock);
	ret = vault_seal_locked(idx, src);
	mutex_unlock(&V.lock);
	return ret;
}

u64 mmg_vault_nonce(unsigned int idx)
{
	u64 n;

	mutex_lock(&V.lock);
	n = V.pg[idx].nonce;
	mutex_unlock(&V.lock);
	return n;
}

int mmg_vault_load(u32 offset, const u8 *data, u32 len)
{
	struct page *tmp;
	void *buf;
	u32 done = 0;
	int ret = 0;

	if ((u64)offset + len > (u64)MMG_PAGES * PAGE_SIZE)
		return -EINVAL;
	tmp = alloc_page(GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;
	buf = page_address(tmp);

	while (done < len && !ret) {
		u32 pos = offset + done;
		unsigned int idx = pos / PAGE_SIZE;
		u32 in_pg = pos % PAGE_SIZE;
		u32 n = min_t(u32, len - done, PAGE_SIZE - in_pg);

		/* Si se reescribe la página completa no hace falta (ni conviene) leer la anterior:
		 * así el administrador puede reprovisionar una página cuyo cifrado fue alterado. */
		if (n == PAGE_SIZE)
			ret = 0;
		else
			ret = mmg_vault_read_page(idx, buf, NULL);   /* descifra la página actual */
		if (!ret) {
			memcpy(buf + in_pg, data + done, n);
			ret = mmg_vault_write_page(idx, buf); /* y la vuelve a cifrar con nonce nuevo */
		}
		done += n;
	}
	memzero_explicit(buf, PAGE_SIZE);
	__free_page(tmp);
	return ret;
}

int mmg_vault_verify_all(void)
{
	int i, bad = 0;

	mutex_lock(&V.lock);
	for (i = 0; i < MMG_PAGES; i++) {
		if (vault_check_locked(i)) {
			bad++;
			mmg_count(MMG_C_INTEG_FAIL);
			mmg_log(MMG_EV_INTEGRITY, "VERIFY pagina=%d MAC invalido (cifrado alterado)", i);
		}
	}
	mutex_unlock(&V.lock);
	return bad;
}

/* Depuración: simula que algo (DMA, rowhammer, un módulo malicioso) altera el cifrado. */
int mmg_vault_dbg_tamper(unsigned int idx)
{
	u8 *p;

	if (idx >= MMG_PAGES)
		return -EINVAL;
	mutex_lock(&V.lock);
	p = page_address(V.pg[idx].ct);
	p[123] ^= 0x01;
	mutex_unlock(&V.lock);
	mmg_log(MMG_EV_ADMIN, "MODO DEPURACION: voltea 1 bit del cifrado de la pagina %u", idx);
	return 0;
}

int mmg_vault_dbg_dump(struct mmguard_dump *d)
{
	void __user *up = u64_to_user_ptr(d->ptr);
	int ret = 0;

	if (d->page >= MMG_PAGES || d->len > PAGE_SIZE)
		return -EINVAL;
	mutex_lock(&V.lock);
	d->kaddr = (u64)(unsigned long)page_address(V.pg[d->page].ct);
	d->nonce = V.pg[d->page].nonce;
	if (d->len && copy_to_user(up, page_address(V.pg[d->page].ct), d->len))
		ret = -EFAULT;
	mutex_unlock(&V.lock);
	return ret;
}

/* ------------------------------ ciclo de vida -------------------------- */

#define MMG_SECRET_P0 \
	"TOP-SECRET mmguard: la clave de la boveda nunca sale del kernel. " \
	"Codigo de lanzamiento = 7-4-1-9-EAFIT-SO-2026.\n"

static void vault_fill_demo(void *buf, unsigned int idx)
{
	memset(buf, 0, PAGE_SIZE);
	if (idx == 0)
		strscpy(buf, MMG_SECRET_P0, PAGE_SIZE);
	else
		scnprintf(buf, PAGE_SIZE, "PAGINA-%02u: contenido protegido de la boveda, pagina numero %u.\n",
			  idx, idx);
}

int mmg_vault_init(void)
{
	struct page *plain;
	int i, ret;

	mutex_init(&V.lock);
	V.cipher = crypto_alloc_skcipher("ctr(aes)", 0, 0);
	if (IS_ERR(V.cipher)) {
		ret = PTR_ERR(V.cipher);
		pr_err("no se pudo obtener ctr(aes): %d\n", ret);
		V.cipher = NULL;
		return ret;
	}
	V.hmac = crypto_alloc_shash("hmac(sha256)", 0, 0);
	if (IS_ERR(V.hmac)) {
		ret = PTR_ERR(V.hmac);
		V.hmac = NULL;
		goto err_cipher;
	}
	V.sha = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(V.sha)) {
		ret = PTR_ERR(V.sha);
		V.sha = NULL;
		goto err_hmac;
	}

	get_random_bytes(V.enc_key, sizeof(V.enc_key));
	get_random_bytes(V.mac_key, sizeof(V.mac_key));
	ret = crypto_skcipher_setkey(V.cipher, V.enc_key, sizeof(V.enc_key));
	if (!ret)
		ret = crypto_shash_setkey(V.hmac, V.mac_key, sizeof(V.mac_key));
	if (ret)
		goto err_sha;

	plain = alloc_page(GFP_KERNEL);
	if (!plain) {
		ret = -ENOMEM;
		goto err_sha;
	}
	for (i = 0; i < MMG_PAGES; i++) {
		V.pg[i].ct = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!V.pg[i].ct) {
			ret = -ENOMEM;
			goto err_pages;
		}
		vault_fill_demo(page_address(plain), i);
		ret = vault_seal_locked(i, page_address(plain));
		if (ret)
			goto err_pages;
	}
	memzero_explicit(page_address(plain), PAGE_SIZE);
	__free_page(plain);
	pr_info("boveda lista: %d paginas cifradas con %s\n", MMG_PAGES,
		crypto_skcipher_driver_name(V.cipher));
	return 0;

err_pages:
	memzero_explicit(page_address(plain), PAGE_SIZE);
	__free_page(plain);
	for (i = 0; i < MMG_PAGES; i++)
		if (V.pg[i].ct)
			__free_page(V.pg[i].ct);
err_sha:
	crypto_free_shash(V.sha);
err_hmac:
	crypto_free_shash(V.hmac);
err_cipher:
	crypto_free_skcipher(V.cipher);
	return ret;
}

void mmg_vault_exit(void)
{
	int i;

	for (i = 0; i < MMG_PAGES; i++) {
		if (V.pg[i].ct) {
			memzero_explicit(page_address(V.pg[i].ct), PAGE_SIZE);
			__free_page(V.pg[i].ct);
		}
	}
	memzero_explicit(V.enc_key, sizeof(V.enc_key));
	memzero_explicit(V.mac_key, sizeof(V.mac_key));
	crypto_free_shash(V.sha);
	crypto_free_shash(V.hmac);
	crypto_free_skcipher(V.cipher);
}
