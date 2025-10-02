/* SPDX-License-Identifier: GPL-2.0-or-later */
/* SCTP kernel implementation
 * (C) Copyright Red Hat Inc. 2025
 *
 * These are definitions used by the DTLS chunk, defined in RFC
 * DTLS chunk (https://tools.ietf.org/html/draft-westerlund-tsvwg-sctp-dtls-chunk-05)
 *
 * Please send any bug reports or fixes you make to the
 * email addresses:
 *    lksctp developers <linux-sctp@vger.kernel.org>
 *
 * Written or modified by:
 *   Xin Long <lucien.xin@gmail.com>
 */

#ifndef __sctp_dtls_h__
#define __sctp_dtls_h__

#include <crypto/skcipher.h>
#include <crypto/aead.h>
#include <linux/sctp.h>
#include <net/tls.h>

#define SCTP_EPOCH_MASK		0x3

#define SCTP_PRE_PADDING	1
#define SCTP_UNIHDR_LEN		1
#define SCTP_SEQNUM_LEN		2

#define SCTP_CONTENT_TYPE_LEN	1
#define SCTP_TAG_SIZE		16
#define SCTP_POST_PADDING	3

#define SCTP_DTLS_HEAD		(sizeof(struct sctp_chunkhdr) + \
				 SCTP_PRE_PADDING + SCTP_UNIHDR_LEN + \
				 SCTP_SEQNUM_LEN)

#define SCTP_DTLS_OVERHEAD	(SCTP_DTLS_HEAD + SCTP_CONTENT_TYPE_LEN + \
				 SCTP_TAG_SIZE + SCTP_POST_PADDING)

#define SCTP_MAX_PMIDS_LEN	128

#define SCTP_CIPHER_MIN		TLS_CIPHER_AES_GCM_128
#define SCTP_CIPHER_MAX		TLS_CIPHER_CHACHA20_POLY1305

struct sctp_kmp {
	__u8 *data;
	__u16 len;
};

struct sctp_crypto {
	struct crypto_skcipher *skc;
	struct crypto_aead *aead;

	__u8 sn_key[SCTP_MAX_KEY_SIZE];
	__u8 key[SCTP_MAX_KEY_SIZE];
	__u8 iv[SCTP_IV_SIZE];

	__u16 epoch;
	__u16 users;
	__u8 chacha;
	__u8 ccm;
};

enum {
	SCTP_CRYPTO_DATA,
	SCTP_CRYPTO_RESTART,
	SCTP_CRYPTO_MAX
};

struct sctp_dtls {
	struct sctp_crypto *recv_crypto[SCTP_CRYPTO_MAX][SCTP_EPOCH_MASK + 1];
	struct sctp_crypto *send_crypto[SCTP_CRYPTO_MAX];

	struct sctp_kmp chosen_kmp;
	struct sctp_kmp local_kmp;
	struct sctp_kmp peer_kmp;

	__u64 send_seq_num;
	__u64 recv_seq_num;
	__u32 replay_window;
	__u8 force_crypto:1;
	__u8 strict:1;

	struct {
		__u64 dropped_unprotected;
		__u64 aead_failures;
		__u64 recv_protected;
		__u64 sent_protected;
	} stats;
};

#define SCTP_DTLS_TIEB_LEN	4
#define SCTP_DTLS_FLAGS_LEN	1

#define SCTP_DTLS_PMID_OFF	(SCTP_DTLS_TIEB_LEN + SCTP_DTLS_FLAGS_LEN)

static inline bool sctp_kmp_pmids_match(struct sctp_kmp *kmp, __u8 pmid)
{
	__u8 *p, *end;

	p = kmp->data + SCTP_DTLS_PMID_OFF;
	end = &p[kmp->len - SCTP_DTLS_PMID_OFF];

	for (; p < end; p++) {
		if (*p == pmid)
			return true;
	}
	return false;
}

static inline bool sctp_kmp_has_restart(struct sctp_kmp *kmp)
{
	if (!kmp->len)
		return false;
	return !!(*(kmp->data + SCTP_DTLS_TIEB_LEN) & SCTP_DTLS_RESTART);
}

static inline bool sctp_kmp_get_match(struct sctp_kmp *lkmp,
				      struct sctp_kmp *param, __u8 *flags,
				      __u8 *pmid, __be16 *code)
{
	__u32 rtieb = get_unaligned_be32(param->data);
	__u32 ltieb = get_unaligned_be32(lkmp->data);
	__u8 rflags = *(param->data + sizeof(rtieb));
	__u8 lflags = *(lkmp->data + sizeof(ltieb));
	__u8 *p, *end;

	if (ltieb == rtieb) {
		*code = SCTP_ERROR_DTLS_TIE_BREAKER;
		return false;
	}
	if ((lflags & SCTP_DTLS_CLIENT) && (lflags & SCTP_DTLS_SERVER)) {
		if ((rflags & SCTP_DTLS_CLIENT) &&
		    (rflags & SCTP_DTLS_SERVER)) {
			*flags = ltieb > rtieb ? SCTP_DTLS_SERVER :
						 SCTP_DTLS_CLIENT;
		} else if (rflags & SCTP_DTLS_CLIENT) {
			*flags = SCTP_DTLS_SERVER;
		} else if (rflags & SCTP_DTLS_SERVER) {
			*flags = SCTP_DTLS_CLIENT;
		} else {
			*code = SCTP_ERROR_DTLS_ROLE;
			return false;
		}
	} else if (lflags & SCTP_DTLS_CLIENT) {
		if (!(rflags & SCTP_DTLS_SERVER)) {
			*code = SCTP_ERROR_DTLS_ROLE;
			return false;
		}
		*flags = SCTP_DTLS_CLIENT;
	} else if (lflags & SCTP_DTLS_SERVER) {
		if (!(rflags & SCTP_DTLS_CLIENT)) {
			*code = SCTP_ERROR_DTLS_ROLE;
			return false;
		}
		*flags = SCTP_DTLS_SERVER;
	} else {
		*code = SCTP_ERROR_DTLS_ROLE;
		return false;
	}
	if ((lflags & SCTP_DTLS_RESTART) && (rflags & SCTP_DTLS_RESTART))
		*flags |= SCTP_DTLS_RESTART;

	if (*flags & SCTP_DTLS_SERVER) {
		p = lkmp->data + SCTP_DTLS_PMID_OFF;
		end = &p[lkmp->len - SCTP_DTLS_PMID_OFF];
		for (; p < end; p++) {
			if (sctp_kmp_pmids_match(param, *p)) {
				*pmid = *p;
				return true;
			}
		}
	} else {
		p = param->data + SCTP_DTLS_PMID_OFF;
		end = &p[param->len - SCTP_DTLS_PMID_OFF];
		for (; p < end; p++) {
			if (sctp_kmp_pmids_match(lkmp, *p)) {
				*pmid = *p;
				return true;
			}
		}
	}
	*flags = 0;
	*code = SCTP_ERROR_DTLS_METHOD;
	return false;
}

static inline int sctp_kmp_copy_match(struct sctp_kmp *ckmp,
				      struct sctp_kmp *lkmp,
				      struct sctp_kmp *param, gfp_t gfp)
{
	__u8 flags = 0, *data, pmid;
	__be16 code = 0;

	if (!sctp_kmp_get_match(lkmp, param, &flags, &pmid, &code))
		return 0;

	data = kzalloc(SCTP_DTLS_PMID_OFF + sizeof(pmid), gfp);
	if (!data)
		return -ENOMEM;

	memcpy(data, lkmp->data, SCTP_DTLS_TIEB_LEN);
	memcpy(data + SCTP_DTLS_TIEB_LEN, &flags, sizeof(flags));
	memcpy(data + SCTP_DTLS_PMID_OFF, &pmid, sizeof(pmid));

	kfree(ckmp->data);
	ckmp->data = data;
	ckmp->len = SCTP_DTLS_PMID_OFF + sizeof(pmid);
	return 0;
}

static inline __u64 sctp_dtls_get_seq_num(__u64 max_recv_seq_num, __u16 seq_num)
{
	__u64 window = BIT_ULL(BYTES_TO_BITS(SCTP_SEQNUM_LEN));
	__u64 base = max_recv_seq_num & ~(window - 1);
	__u64 candidate = base | seq_num;

	if (candidate + (window >> 1) <= max_recv_seq_num)
		candidate += window;
	else if (candidate > max_recv_seq_num + (window >> 1))
		candidate -= window;

	return candidate;
}

static inline int sctp_kmp_set(struct sctp_kmp *lkmp, __u8 flags, __u8 *pmids,
			       __u16 plen, gfp_t gfp)
{
	__u8 *data;
	__u32 tieb;

	if (!plen)
		return 0;

	data = kzalloc(sizeof(tieb) + sizeof(flags) + plen, gfp);
	if (!data)
		return -ENOMEM;

	/* Tie breaker | flags | kmp[] */
	tieb = get_random_u32();
	put_unaligned_be32(tieb, data);
	memcpy(data + sizeof(tieb), &flags, sizeof(flags));
	memcpy(data + sizeof(tieb) + sizeof(flags), pmids, plen);

	kfree(lkmp->data);
	lkmp->data = data;
	lkmp->len = sizeof(tieb) + sizeof(flags) + plen;
	return 0;
}

static inline void sctp_kmp_free(struct sctp_kmp *kmp)
{
	kfree(kmp->data);
	kmp->data = NULL;
	kmp->len = 0;
}

static inline int sctp_kmp_dup(struct sctp_kmp *to, const struct sctp_kmp *from,
			       gfp_t gfp)
{
	__u8 *data;

	if (!from->data) {
		sctp_kmp_free(to);
		return 0;
	}

	data = kmemdup(from->data, from->len, gfp);
	if (!data)
		return -ENOMEM;

	kfree(to->data);
	to->data = data;
	to->len = from->len;
	return 0;
}

static inline int sctp_dtls_copy_kmps(struct sctp_dtls *new_dtls,
				      struct sctp_dtls *dtls)
{
	if (sctp_kmp_dup(&new_dtls->chosen_kmp, &dtls->chosen_kmp, GFP_ATOMIC))
		return -ENOMEM;
	if (sctp_kmp_dup(&new_dtls->local_kmp, &dtls->local_kmp, GFP_ATOMIC))
		return -ENOMEM;
	return sctp_kmp_dup(&new_dtls->peer_kmp, &dtls->peer_kmp, GFP_ATOMIC);
}

static inline void sctp_crypto_destroy(struct sctp_crypto *crypto)
{
	crypto_free_aead(crypto->aead);
	crypto_free_skcipher(crypto->skc);
	kfree_sensitive(crypto);
}

static inline void sctp_crypto_put(struct sctp_crypto *crypto)
{
	if (crypto && !(--crypto->users))
		sctp_crypto_destroy(crypto);
}

static inline struct sctp_crypto *sctp_crypto_get(struct sctp_crypto *crypto)
{
	if (crypto)
		crypto->users++;
	return crypto;
}

static inline void sctp_dtls_copy_crypto(struct sctp_dtls *new_dtls,
					 struct sctp_dtls *dtls, __u8 r)
{
	int e;

	sctp_crypto_put(new_dtls->send_crypto[r]);
	new_dtls->send_crypto[r] = sctp_crypto_get(dtls->send_crypto[r]);

	for (e = 0; e <= SCTP_EPOCH_MASK; e++) {
		sctp_crypto_put(new_dtls->recv_crypto[r][e]);
		new_dtls->recv_crypto[r][e] =
			sctp_crypto_get(dtls->recv_crypto[r][e]);
	}
}

static inline void sctp_dtls_destroy(struct sctp_dtls *dtls)
{
	int r, e;

	sctp_kmp_free(&dtls->chosen_kmp);
	sctp_kmp_free(&dtls->local_kmp);
	sctp_kmp_free(&dtls->peer_kmp);

	for (r = 0; r < SCTP_CRYPTO_MAX; r++) {
		sctp_crypto_put(dtls->send_crypto[r]);
		for (e = 0; e <= SCTP_EPOCH_MASK; e++)
			sctp_crypto_put(dtls->recv_crypto[r][e]);
	}
}

int sctp_dtls_encode_record(struct sctp_dtls *dtls, struct sk_buff *skb,
			    void (*cb)(void *data, int err), gfp_t gfp,
			    __u8 resume);
int sctp_dtls_decode_record(struct sctp_dtls *dtls, struct sk_buff *skb,
			    void (*cb)(void *data, int err), gfp_t gfp,
			    __u8 resume);

int sctp_dtls_set_send_keys(struct sctp_dtls *dtls,
			    struct sctp_dtls_keys *params);
int sctp_dtls_add_recv_keys(struct sctp_dtls *dtls,
			    struct sctp_dtls_keys *params);
int sctp_dtls_del_recv_keys(struct sctp_dtls *dtls,
			    struct sctp_dtls_keys_id *params);

void sctp_dtls_get_cipher_suites(char *buf, size_t maxlen);

#endif
