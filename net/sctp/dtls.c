// SPDX-License-Identifier: GPL-2.0-or-later
/* SCTP kernel implementation
 * (C) Copyright Red Hat Inc. 2025
 *
 * This file is part of the SCTP kernel implementation
 *
 * These are definitions used by the DTLS chunk, defined in RFC
 * DTLS chunk (https://tools.ietf.org/html/draft-westerlund-tsvwg-sctp-dtls-chunk-05)
 *
 * Please send any bug reports or fixes you make to the
 * email address(es):
 *    lksctp developers <linux-sctp@vger.kernel.org>
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#include <net/sctp/sctp.h>

/* DTLS 1.3 Unified Header:
 *
 *  0 1 2 3 4 5 6 7
 *  +-+-+-+-+-+-+-+-+
 *  |0|0|1|C|S|L|E E|
 *  +-+-+-+-+-+-+-+-+
 *  | Connection ID |   Legend:
 *  | (if any,      |
 *  /  length as    /   C   - Connection ID (CID) present
 *  |  negotiated)  |   S   - Sequence number length
 *  +-+-+-+-+-+-+-+-+   L   - Length present
 *  |  8 or 16 bit  |   E   - Epoch
 *  |Sequence Number|
 *  +-+-+-+-+-+-+-+-+
 *  | 16 bit Length |
 *  | (if present)  |
 *  +-+-+-+-+-+-+-+-+
 */

struct sctp_dtls_unihdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8   e:2,    /* Epoch */
	     l:1,    /* Length present */
	     s:1,    /* Sequence number length */
	     c:1,    /* Connection ID present */
	     one:1,  /* must be 1 */
	     zero:2; /* must be 0 */
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8   zero:2, /* must be 0 */
	     one:1,  /* must be 1 */
	     c:1,    /* Connection ID present */
	     s:1,    /* Sequence number length */
	     l:1,    /* Length present */
	     e:2;    /* Epoch */
#endif
};

static struct sctp_dtls_unihdr *sctp_dtls_unihdr(u8 *p)
{
	return (struct sctp_dtls_unihdr *)p;
}

struct sctp_dtls_cipher_desc {
	u32 keylen;
	u16 suite;
	char *cipher_name;
	char *skc_name;
};

#define CIPHER_DESC(type, id, algname, skcname)[type - SCTP_CIPHER_MIN] = { \
	.keylen = type ## _KEY_SIZE, \
	.suite = id, \
	.cipher_name = algname, \
	.skc_name = skcname, \
}

const struct sctp_dtls_cipher_desc sctp_dtls_cipher_desc[SCTP_CIPHER_MAX + 1 -
							 SCTP_CIPHER_MIN] = {
	CIPHER_DESC(TLS_CIPHER_AES_GCM_128, 0x1301, "gcm(aes)", "ecb(aes)"),
	CIPHER_DESC(TLS_CIPHER_AES_GCM_256, 0x1302, "gcm(aes)", "ecb(aes)"),
	CIPHER_DESC(TLS_CIPHER_AES_CCM_128, 0x1304, "ccm(aes)", "ecb(aes)"),
	CIPHER_DESC(TLS_CIPHER_CHACHA20_POLY1305, 0x1303,
		    "rfc7539(chacha20,poly1305)", "chacha20"),
};

static const struct sctp_dtls_cipher_desc *sctp_dtls_get_cipher_desc(u16 type)
{
	const struct sctp_dtls_cipher_desc *cipher;

	cipher = &sctp_dtls_cipher_desc[type - SCTP_CIPHER_MIN];
	if (!cipher->suite)
		return NULL;
	return cipher;
}

static u16 sctp_get_cipher_type(u16 suit)
{
	const struct sctp_dtls_cipher_desc *cipher;
	u16 type;

	for (type = SCTP_CIPHER_MIN; type <= SCTP_CIPHER_MAX; type++) {
		cipher = sctp_dtls_get_cipher_desc(type);
		if (!cipher)
			continue;
		if (cipher->suite == suit)
			return type;
	}
	return 0;
}

void sctp_dtls_get_cipher_suites(char *buf, size_t maxlen)
{
	const struct sctp_dtls_cipher_desc *cipher;
	size_t offs = 0;
	u16 type;

	for (type = SCTP_CIPHER_MIN; type <= SCTP_CIPHER_MAX; type++) {
		cipher = sctp_dtls_get_cipher_desc(type);
		if (!cipher)
			continue;
		offs += snprintf(buf + offs, maxlen - offs,
				 "%s0x%02x,0x%02x:%s-%u", offs == 0 ? "" : " ",
				 cipher->suite >> 8, cipher->suite & 0xf,
				 cipher->cipher_name, cipher->keylen * 8);
		if (WARN_ON_ONCE(offs >= maxlen))
			break;
	}
}

#define SCTP_EPOCH_MIN		3

static int sctp_dtls_set_crypto_keys(struct sctp_crypto *crypto,
				     struct sctp_dtls_keys *params)
{
	const struct sctp_dtls_cipher_desc *cipher;
	void *tfm;
	u16 type;

	if (params->sdk_epoch < SCTP_EPOCH_MIN)
		return -EINVAL;

	type = sctp_get_cipher_type((params->sdk_cipher_suite[0] << 8 |
				     params->sdk_cipher_suite[1]));
	if (!type)
		return -EINVAL;
	cipher = sctp_dtls_get_cipher_desc(type);
	if (!cipher)
		return -EINVAL;

	if (params->sdk_key_len != cipher->keylen ||
	    params->sdk_iv_len != SCTP_IV_SIZE ||
	    params->sdk_sn_key_len != cipher->keylen)
		return -EINVAL;

	tfm = crypto_alloc_aead(cipher->cipher_name, 0, 0);
	if (IS_ERR(tfm))
		return -ENOMEM;
	crypto->aead = tfm;

	tfm = crypto_alloc_sync_skcipher(cipher->skc_name, 0, 0);
	if (IS_ERR(tfm)) {
		crypto_free_aead(crypto->aead);
		return -ENOMEM;
	}
	crypto->skc = tfm;
	crypto->epoch = params->sdk_epoch;
	crypto->chacha = (type == TLS_CIPHER_CHACHA20_POLY1305);
	crypto->ccm = (type == TLS_CIPHER_AES_CCM_128 ||
		       type == TLS_CIPHER_SM4_CCM);

	memcpy(crypto->key, params->sdk_keys, cipher->keylen);
	memcpy(crypto->iv, params->sdk_keys + params->sdk_key_len,
	       SCTP_IV_SIZE);
	memcpy(crypto->sn_key,
	       params->sdk_keys + params->sdk_key_len + params->sdk_iv_len,
	       cipher->keylen);

	crypto_aead_setkey(crypto->aead, crypto->key, cipher->keylen);
	crypto_skcipher_setkey(crypto->skc, crypto->sn_key, cipher->keylen);
	return 0;
}

int sctp_dtls_set_send_keys(struct sctp_dtls *dtls,
			    struct sctp_dtls_keys *params)
{
	struct sctp_crypto *crypto, *old;
	int ret;
	u8 r;

	r = !!params->sdk_restart;
	old = dtls->send_crypto[r];

	crypto = kzalloc_obj(*crypto, GFP_KERNEL);
	if (!crypto)
		return -ENOMEM;

	ret = sctp_dtls_set_crypto_keys(crypto, params);
	if (ret) {
		kfree_sensitive(crypto);
		return ret;
	}

	dtls->send_crypto[r] = sctp_crypto_get(crypto);
	sctp_crypto_put(old);
	return 0;
}

int sctp_dtls_add_recv_keys(struct sctp_dtls *dtls,
			    struct sctp_dtls_keys *params)
{
	struct sctp_crypto *crypto, *old;
	int ret;
	u8 e, r;

	e = params->sdk_epoch & SCTP_EPOCH_MASK;
	r = !!params->sdk_restart;
	old = dtls->recv_crypto[r][e];

	crypto = kzalloc_obj(*crypto, GFP_KERNEL);
	if (!crypto)
		return -ENOMEM;

	ret = sctp_dtls_set_crypto_keys(crypto, params);
	if (ret) {
		kfree_sensitive(crypto);
		return ret;
	}

	dtls->recv_crypto[r][e] = sctp_crypto_get(crypto);
	sctp_crypto_put(old);
	return 0;
}

int sctp_dtls_del_recv_keys(struct sctp_dtls *dtls,
			    struct sctp_dtls_keys_id *params)
{
	struct sctp_crypto *crypto;
	u8 e, r;

	e = params->sdki_epoch & SCTP_EPOCH_MASK;
	r = !!params->sdki_restart;
	crypto = dtls->recv_crypto[r][e];
	if (!crypto || crypto->epoch != params->sdki_epoch)
		return -EINVAL;

	sctp_crypto_put(crypto);
	dtls->recv_crypto[r][e] = NULL;
	return 0;
}

static void *sctp_dtls_aead_mem_alloc(struct crypto_aead *tfm, u32 ctx_size,
				      u8 **iv, struct aead_request **req,
				      struct scatterlist **sg, u32 nsg,
				      gfp_t gfp)
{
	unsigned int iv_size, req_size;
	unsigned int len;
	u8 *mem;

	iv_size = crypto_aead_ivsize(tfm);
	req_size = sizeof(**req) + crypto_aead_reqsize(tfm);

	len = ctx_size;
	len += iv_size;
	len += crypto_aead_alignmask(tfm) & ~(crypto_tfm_ctx_alignment() - 1);
	len = ALIGN(len, crypto_tfm_ctx_alignment());
	len += req_size;
	len = ALIGN(len, __alignof__(struct scatterlist));
	len += nsg * sizeof(**sg);

	mem = kzalloc(len, gfp);
	if (!mem)
		return NULL;

	*iv = (u8 *)PTR_ALIGN(mem + ctx_size, crypto_aead_alignmask(tfm) + 1);
	*req = (struct aead_request *)PTR_ALIGN(*iv + iv_size,
			crypto_tfm_ctx_alignment());
	*sg = (struct scatterlist *)PTR_ALIGN((u8 *)*req + req_size,
			__alignof__(struct scatterlist));

	return (void *)mem;
}

static void *sctp_dtls_skcipher_mem_alloc(struct crypto_skcipher *tfm,
					  u32 mask_size, u8 **iv,
					  struct skcipher_request **req,
					  gfp_t gfp)
{
	unsigned int iv_size, req_size;
	unsigned int len;
	u8 *mem;

	iv_size = crypto_skcipher_ivsize(tfm);
	req_size = sizeof(**req) + crypto_skcipher_reqsize(tfm);

	len = mask_size;
	len += iv_size;
	len += crypto_skcipher_alignmask(tfm) &
	       ~(crypto_tfm_ctx_alignment() - 1);
	len = ALIGN(len, crypto_tfm_ctx_alignment());
	len += req_size;

	mem = kzalloc(len, gfp);
	if (!mem)
		return NULL;

	*iv = (u8 *)PTR_ALIGN(mem + mask_size,
			      crypto_skcipher_alignmask(tfm) + 1);
	*req = (struct skcipher_request *)PTR_ALIGN(*iv + iv_size,
			crypto_tfm_ctx_alignment());

	return (void *)mem;
}

#define SCTP_SEQNUM_MASK_LEN	16

static int sctp_dtls_header_encrypt(struct sctp_crypto *crypto,
				    struct sk_buff *skb, gfp_t gfp,
				    int seq_len, int hlen)
{
	struct crypto_skcipher *tfm = crypto->skc;
	struct skcipher_request *req;
	struct scatterlist sg;
	u8 *mask, *iv, *p;
	int err, i;

	mask = sctp_dtls_skcipher_mem_alloc(tfm, SCTP_SEQNUM_MASK_LEN, &iv,
					    &req, gfp);
	if (!mask)
		return -ENOMEM;

	p = skb->data + hlen;
	memcpy((crypto->chacha ? iv : mask), p, SCTP_SEQNUM_MASK_LEN);
	sg_init_one(&sg, mask, SCTP_SEQNUM_MASK_LEN);
	skcipher_request_set_tfm(req, tfm);
	skcipher_request_set_crypt(req, &sg, &sg, SCTP_SEQNUM_MASK_LEN, iv);
	err = crypto_skcipher_encrypt(req);
	if (err)
		goto err;

	p -= seq_len;
	for (i = 0; i < seq_len; i++)
		p[i] ^= mask[i];
err:
	kfree_sensitive(mask);
	return err;
}

static int sctp_dtls_payload_encrypt(struct sctp_crypto *crypto,
				     struct sk_buff *skb,
				     void (*cb)(void *data, int err), gfp_t gfp,
				     __be64 seq_num, int offset, int hlen)
{
	struct crypto_aead *tfm = crypto->aead;
	u8 *iv, nonce[SCTP_IV_SIZE];
	struct aead_request *req;
	struct sk_buff *trailer;
	struct scatterlist *sg;
	int err, nsg, len, i;
	void *ctx;

	len = skb->len;
	err = skb_cow_data(skb, SCTP_TAG_SIZE, &trailer);
	if (err < 0)
		return err;
	nsg = err;
	pskb_put(skb, trailer, SCTP_TAG_SIZE);
	ctx = sctp_dtls_aead_mem_alloc(tfm, 0, &iv, &req, &sg, nsg, gfp);
	if (!ctx)
		return -ENOMEM;

	sg_init_table(sg, nsg);
	err = skb_to_sgvec(skb, sg, offset, skb->len - offset);
	if (err < 0)
		goto err;

	memcpy(nonce, crypto->iv, SCTP_IV_SIZE);
	for (i = 0; i < sizeof(seq_num); i++)
		nonce[SCTP_IV_SIZE - sizeof(seq_num) + i] ^=
			((u8 *)&seq_num)[i];
	iv[0] = TLS_AES_CCM_IV_B0_BYTE;
	memcpy(&iv[crypto->ccm], nonce, SCTP_IV_SIZE - crypto->ccm);

	aead_request_set_tfm(req, tfm);
	aead_request_set_ad(req, hlen);
	aead_request_set_crypt(req, sg, sg, len - offset - hlen, iv);
	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, cb, skb);

	/* May complete asynchronously; set crypto_ctx to free ctx in cb. */
	SCTP_OUTPUT_CB(skb)->crypto_ctx = ctx;
	err = crypto_aead_encrypt(req);
	if (err == -EINPROGRESS || err == -EBUSY)
		return -EINPROGRESS;
err:
	kfree_sensitive(ctx);
	return err;
}

#define SCTP_CONTENT_TYPE_APP	23

int sctp_dtls_encode_record(struct sctp_dtls *dtls, struct sk_buff *skb,
			    void (*cb)(void *data, int err), gfp_t gfp,
			    u8 resume)
{
	struct sctp_dtls_unihdr *unihdr;
	struct sctp_crypto *crypto;
	int err, len, hlen, offset;
	struct sctp_chunkhdr *ch;
	u64 seq_num;
	u8 *p;

	ch = (struct sctp_chunkhdr *)(skb->data + sizeof(struct sctphdr));
	crypto = dtls->send_crypto[sctp_test_R_bit(ch)];
	if (!crypto)
		return -EINVAL;

	/* Build Unified Header. */
	offset = sizeof(struct sctphdr) + sizeof(struct sctp_chunkhdr) +
		 SCTP_PRE_PADDING;
	p = skb->data + offset;

	memset(p - SCTP_PRE_PADDING, 0, SCTP_PRE_PADDING);

	unihdr = sctp_dtls_unihdr(p);
	unihdr->e = crypto->epoch;
	unihdr->l = 0;
	unihdr->s = 1;
	unihdr->c = 0;
	unihdr->one = 1;
	unihdr->zero = 0;
	p += SCTP_UNIHDR_LEN;
	hlen = SCTP_UNIHDR_LEN;

	seq_num = dtls->send_seq_num++;
	put_unaligned_be16(seq_num & U16_MAX, p);
	hlen += SCTP_SEQNUM_LEN;

	if (resume)
		goto out;

	p = skb_put(skb, SCTP_CONTENT_TYPE_LEN);
	*p = SCTP_CONTENT_TYPE_APP;

	/* Payload Protection. */
	err = sctp_dtls_payload_encrypt(crypto, skb, cb, gfp,
					cpu_to_be64(seq_num), offset, hlen);
	if (err)
		return err;

out:
	/* Header Protection. */
	err = sctp_dtls_header_encrypt(crypto, skb, gfp, SCTP_SEQNUM_LEN,
				       offset + hlen);
	if (err)
		return err;

	/* chunk/skb Update. */
	dtls->stats.sent_protected++;
	len = skb->len - sizeof(struct sctphdr);
	ch->length = htons(len);

	len = SCTP_PAD4(len) - len;
	skb_put_zero(skb, len);
	WARN_ON_ONCE(len != SCTP_POST_PADDING);
	return 0;
}

#define SCTP_SEQNUM_MIN_LEN	1
#define SCTP_LENGTH_LEN		2

static int sctp_dtls_header_decrypt(struct sctp_crypto *crypto,
				    struct sk_buff *skb, gfp_t gfp,
				    u64 *seq_num, int seq_len, int hlen)
{
	struct crypto_skcipher *tfm = crypto->skc;
	struct skcipher_request *req;
	struct sk_buff *trailer;
	struct scatterlist sg;
	u8 *mask, *iv, *p;
	int err, i;

	err = skb_cow_data(skb, 0, &trailer);
	if (err < 0)
		return err;

	mask = sctp_dtls_skcipher_mem_alloc(tfm, SCTP_SEQNUM_MASK_LEN,
					    &iv, &req, gfp);
	if (!mask)
		return -ENOMEM;

	p = skb->data + hlen;
	memcpy((crypto->chacha ? iv : mask), p, SCTP_SEQNUM_MASK_LEN);
	sg_init_one(&sg, mask, SCTP_SEQNUM_MASK_LEN);
	skcipher_request_set_tfm(req, tfm);
	skcipher_request_set_crypt(req, &sg, &sg, SCTP_SEQNUM_MASK_LEN, iv);
	err = crypto_skcipher_encrypt(req);
	if (err)
		goto err;

	p -= seq_len;
	for (i = 0; i < seq_len; i++)
		p[i] ^= mask[i];

	if (seq_len == SCTP_SEQNUM_MIN_LEN)
		*seq_num = *p;
	else
		*seq_num = get_unaligned_be16(p);
err:
	kfree_sensitive(mask);
	return err;
}

static int sctp_dtls_payload_decrypt(struct sctp_crypto *crypto,
				     struct sk_buff *skb,
				     void (*cb)(void *data, int err), gfp_t gfp,
				     __be64 seq_num, int offset, int hlen)
{
	struct crypto_aead *tfm = crypto->aead;
	u8 *iv, nonce[SCTP_IV_SIZE];
	struct aead_request *req;
	struct scatterlist *sg;
	int err, len, i, nsg;
	void *ctx;

	nsg = 1;
	ctx = sctp_dtls_aead_mem_alloc(tfm, 0, &iv, &req, &sg, nsg, gfp);
	if (!ctx)
		return -ENOMEM;

	sg_init_table(sg, nsg);
	len = skb->len;
	err = skb_to_sgvec(skb, sg, offset, len - offset);
	if (err < 0)
		goto err;

	memcpy(nonce, crypto->iv, SCTP_IV_SIZE);
	for (i = 0; i < sizeof(seq_num); i++)
		nonce[SCTP_IV_SIZE - sizeof(seq_num) + i] ^=
			((u8 *)&seq_num)[i];
	iv[0] = TLS_AES_CCM_IV_B0_BYTE;
	memcpy(&iv[crypto->ccm], nonce, SCTP_IV_SIZE - crypto->ccm);

	aead_request_set_tfm(req, tfm);
	aead_request_set_ad(req, hlen);
	aead_request_set_crypt(req, sg, sg, len - offset - hlen, iv);
	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, cb, skb);

	SCTP_INPUT_CB(skb)->crypto_ctx = ctx;
	err = crypto_aead_decrypt(req);
	if (err == -EINPROGRESS || err == -EBUSY)
		return -EINPROGRESS;
err:
	kfree_sensitive(ctx);
	return err;
}

int sctp_dtls_decode_record(struct sctp_dtls *dtls, struct sk_buff *skb,
			    void (*cb)(void *data, int err), gfp_t gfp,
			    u8 resume)
{
	int err, len, offset, hlen, seq_len;
	struct sctp_dtls_unihdr *unihdr;
	struct sctp_crypto *crypto;
	struct sctp_chunkhdr *ch;
	u64 seq_num;
	__be16 n;
	u8 *p;

	ch = (struct sctp_chunkhdr *)skb->data;
	len = ntohs(ch->length);
	if (SCTP_PAD4(len) != skb->len)
		return -EINVAL;
	skb_trim(skb, len);

	offset = sizeof(struct sctp_chunkhdr) + SCTP_PRE_PADDING;
	if (skb->len < offset + SCTP_UNIHDR_LEN)
		return -EINVAL;

	p = skb->data + offset;

	unihdr = sctp_dtls_unihdr(p);
	crypto = dtls->recv_crypto[sctp_test_R_bit(ch)][unihdr->e];
	if (!crypto)
		return -EINVAL;

	/* Parse Unifield Header. */
	hlen = SCTP_UNIHDR_LEN;
	p += SCTP_UNIHDR_LEN;
	seq_len = unihdr->s + SCTP_SEQNUM_MIN_LEN;
	if (skb->len < offset + hlen + seq_len)
		return -EINVAL;
	hlen += seq_len;
	p += seq_len;

	if (unihdr->l) { /* Validate the length if exist. */
		if (skb->len < offset + hlen + SCTP_LENGTH_LEN)
			return -EINVAL;
		memcpy(&n, p, SCTP_LENGTH_LEN);
		hlen += SCTP_LENGTH_LEN;
		p += SCTP_LENGTH_LEN;

		len = be16_to_cpu(n);
		if (len + hlen + offset != skb->len)
			return -EINVAL;
	}

	if (skb->len < offset + hlen + SCTP_CONTENT_TYPE_LEN + SCTP_TAG_SIZE)
		return -EINVAL;

	if (resume)
		goto out;

	/* Header Decryption. */
	err = sctp_dtls_header_decrypt(crypto, skb, gfp, &seq_num, seq_len,
				       offset + hlen);
	if (err)
		return err;

	seq_num = sctp_dtls_get_seq_num(dtls->recv_seq_num, (u16)seq_num);
	if (dtls->replay_window && dtls->recv_seq_num > seq_num &&
	    dtls->recv_seq_num - seq_num > dtls->replay_window)
		return -EINVAL;
	if (seq_num > dtls->recv_seq_num)
		dtls->recv_seq_num = seq_num;

	/* Payload Decryption. */
	err = sctp_dtls_payload_decrypt(crypto, skb, cb, gfp,
					cpu_to_be64(seq_num), offset, hlen);
	if (err) {
		if (err != -EINPROGRESS)
			dtls->stats.aead_failures++;
		return err;
	}

out:
	/* chunk/skb Update. */
	len = skb->len - (SCTP_CONTENT_TYPE_LEN + SCTP_TAG_SIZE);
	p = skb->data + len;
	if (*p != SCTP_CONTENT_TYPE_APP)
		return -EINVAL;

	/* chunk/skb Update. */
	dtls->stats.recv_protected++;
	skb_trim(skb, len);
	skb_pull(skb, offset + hlen);
	return 0;
}
