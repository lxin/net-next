// SPDX-License-Identifier: GPL-2.0-or-later
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Initialization/cleanup for QUIC protocol support.
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#include <net/proto_memory.h>

#include "socket.h"

/* ACK Frame {
 *  Type (i) = 0x02..0x03,
 *  Largest Acknowledged (i),
 *  ACK Delay (i),
 *  ACK Range Count (i),
 *  First ACK Range (i),
 *  ACK Range (..) ...,
 *  [ECN Counts (..)],
 * }
 */

static struct quic_frame *
quic_frame_ack_create(struct sock *sk, void *data, u8 type, gfp_t gfp)
{
	return NULL;
}

static struct quic_frame *
quic_frame_ping_create(struct sock *sk, void *data, u8 type, gfp_t gfp)
{
	return NULL;
}

static struct quic_frame *
quic_frame_padding_create(struct sock *sk, void *data, u8 type, gfp_t gfp)
{
	return NULL;
}

static struct quic_frame *
quic_frame_new_token_create(struct sock *sk, void *data, u8 type, gfp_t gfp)
{
	return NULL;
}

/* STREAM Frame {
 *  Type (i) = 0x08..0x0f,
 *  Stream ID (i),
 *  [Offset (i)],
 *  [Length (i)],
 *  Stream Data (..),
 * }
 */

static struct quic_frame *
quic_frame_stream_create(struct sock *sk, void *data, u8 type, gfp_t gfp)
{
	return NULL;
}

static struct quic_frame *
quic_frame_handshake_done_create(struct sock *sk, void *data, u8 type,
				 gfp_t gfp)
{
	return NULL;
}

static struct quic_frame *
quic_frame_crypto_create(struct sock *sk, void *data, u8 type, gfp_t gfp)
{
	return NULL;
}

static struct quic_frame *
quic_frame_retire_conn_id_create(struct sock *sk, void *data, u8 type,
				 gfp_t gfp)
{
	return NULL;
}

static struct quic_frame *
quic_frame_new_conn_id_create(struct sock *sk, void *data, u8 type, gfp_t gfp)
{
	return NULL;
}

static struct quic_frame *
quic_frame_path_response_create(struct sock *sk, void *data, u8 type, gfp_t gfp)
{
	return NULL;
}

static struct quic_frame *
quic_frame_path_challenge_create(struct sock *sk, void *data, u8 type,
				 gfp_t gfp)
{
	return NULL;
}

static struct quic_frame *
quic_frame_reset_stream_create(struct sock *sk, void *data, u8 type, gfp_t gfp)
{
	return NULL;
}

static struct quic_frame *
quic_frame_stop_sending_create(struct sock *sk, void *data, u8 type, gfp_t gfp)
{
	return NULL;
}

static struct quic_frame *
quic_frame_max_data_create(struct sock *sk, void *data, u8 type, gfp_t gfp)
{
	return NULL;
}

static struct quic_frame *
quic_frame_max_stream_data_create(struct sock *sk, void *data, u8 type,
				  gfp_t gfp)
{
	return NULL;
}

static struct quic_frame *
quic_frame_max_streams_uni_create(struct sock *sk, void *data, u8 type,
				  gfp_t gfp)
{
	return NULL;
}

static struct quic_frame *
quic_frame_max_streams_bidi_create(struct sock *sk, void *data, u8 type,
				   gfp_t gfp)
{
	return NULL;
}

static struct quic_frame *
quic_frame_connection_close_create(struct sock *sk, void *data, u8 type,
				   gfp_t gfp)
{
	return NULL;
}

static struct quic_frame *
quic_frame_data_blocked_create(struct sock *sk, void *data, u8 type, gfp_t gfp)
{
	return NULL;
}

static struct quic_frame *
quic_frame_stream_data_blocked_create(struct sock *sk, void *data, u8 type,
				      gfp_t gfp)
{
	return NULL;
}

static struct quic_frame *
quic_frame_streams_blocked_uni_create(struct sock *sk, void *data, u8 type,
				      gfp_t gfp)
{
	return NULL;
}

static struct quic_frame *
quic_frame_streams_blocked_bidi_create(struct sock *sk, void *data, u8 type,
				       gfp_t gfp)
{
	return NULL;
}

static int quic_frame_crypto_process(struct sock *sk, struct quic_frame *frame,
				     u8 type, gfp_t gfp)
{
	return -EOPNOTSUPP;
}

static int quic_frame_stream_process(struct sock *sk, struct quic_frame *frame,
				     u8 type, gfp_t gfp)
{
	return -EOPNOTSUPP;
}

static int quic_frame_ack_process(struct sock *sk, struct quic_frame *frame,
				  u8 type, gfp_t gfp)
{
	return -EOPNOTSUPP;
}

static int quic_frame_new_conn_id_process(struct sock *sk,
					  struct quic_frame *frame, u8 type,
					  gfp_t gfp)
{
	return -EOPNOTSUPP;
}

static int quic_frame_retire_conn_id_process(struct sock *sk,
					     struct quic_frame *frame, u8 type,
					     gfp_t gfp)
{
	return -EOPNOTSUPP;
}

static int quic_frame_new_token_process(struct sock *sk,
					struct quic_frame *frame, u8 type,
					gfp_t gfp)
{
	return -EOPNOTSUPP;
}

static int quic_frame_handshake_done_process(struct sock *sk,
					     struct quic_frame *frame, u8 type,
					     gfp_t gfp)
{
	return -EOPNOTSUPP;
}

static int quic_frame_padding_process(struct sock *sk, struct quic_frame *frame,
				      u8 type, gfp_t gfp)
{
	return -EOPNOTSUPP;
}

static int quic_frame_ping_process(struct sock *sk, struct quic_frame *frame,
				   u8 type, gfp_t gfp)
{
	return -EOPNOTSUPP;
}

static int quic_frame_path_challenge_process(struct sock *sk,
					     struct quic_frame *frame, u8 type,
					     gfp_t gfp)
{
	return -EOPNOTSUPP;
}

static int quic_frame_reset_stream_process(struct sock *sk,
					   struct quic_frame *frame, u8 type,
					   gfp_t gfp)
{
	return -EOPNOTSUPP;
}

static int quic_frame_stop_sending_process(struct sock *sk,
					   struct quic_frame *frame, u8 type,
					   gfp_t gfp)
{
	return -EOPNOTSUPP;
}

static int quic_frame_max_data_process(struct sock *sk,
				       struct quic_frame *frame, u8 type,
				       gfp_t gfp)
{
	return -EOPNOTSUPP;
}

static int quic_frame_max_stream_data_process(struct sock *sk,
					      struct quic_frame *frame, u8 type,
					      gfp_t gfp)
{
	return -EOPNOTSUPP;
}

static int quic_frame_max_streams_uni_process(struct sock *sk,
					      struct quic_frame *frame,
					      u8 type, gfp_t gfp)
{
	return -EOPNOTSUPP;
}

static int quic_frame_max_streams_bidi_process(struct sock *sk,
					       struct quic_frame *frame,
					       u8 type, gfp_t gfp)
{
	return -EOPNOTSUPP;
}

static int quic_frame_connection_close_process(struct sock *sk,
					       struct quic_frame *frame,
					       u8 type, gfp_t gfp)
{
	return -EOPNOTSUPP;
}

static int quic_frame_data_blocked_process(struct sock *sk,
					   struct quic_frame *frame, u8 type,
					   gfp_t gfp)
{
	return -EOPNOTSUPP;
}

static int quic_frame_stream_data_blocked_process(struct sock *sk,
						  struct quic_frame *frame,
						  u8 type, gfp_t gfp)
{
	return -EOPNOTSUPP;
}

static int quic_frame_streams_blocked_uni_process(struct sock *sk,
						  struct quic_frame *frame,
						  u8 type, gfp_t gfp)
{
	return -EOPNOTSUPP;
}

static int quic_frame_streams_blocked_bidi_process(struct sock *sk,
						   struct quic_frame *frame,
						   u8 type, gfp_t gfp)
{
	return -EOPNOTSUPP;
}

static int quic_frame_path_response_process(struct sock *sk,
					    struct quic_frame *frame, u8 type,
					    gfp_t gfp)
{
	return -EOPNOTSUPP;
}

static struct quic_frame *
quic_frame_invalid_create(struct sock *sk, void *data, u8 type, gfp_t gfp)
{
	return NULL;
}

static struct quic_frame *
quic_frame_datagram_create(struct sock *sk, void *data, u8 type, gfp_t gfp)
{
	return NULL;
}

static int quic_frame_invalid_process(struct sock *sk,
				      struct quic_frame *frame, u8 type,
				      gfp_t gfp)
{
	return -EOPNOTSUPP;
}

static int quic_frame_datagram_process(struct sock *sk,
				       struct quic_frame *frame, u8 type,
				       gfp_t gfp)
{
	return -EOPNOTSUPP;
}

static void quic_frame_padding_ack(struct sock *sk, struct quic_frame *frame,
				   gfp_t gfp)
{
}

static void quic_frame_ping_ack(struct sock *sk, struct quic_frame *frame,
				gfp_t gfp)
{
}

static void quic_frame_ack_ack(struct sock *sk, struct quic_frame *frame,
			       gfp_t gfp)
{
}

static void quic_frame_reset_stream_ack(struct sock *sk,
					struct quic_frame *frame, gfp_t gfp)
{
}

static void quic_frame_stop_sending_ack(struct sock *sk,
					struct quic_frame *frame, gfp_t gfp)
{
}

static void quic_frame_crypto_ack(struct sock *sk, struct quic_frame *frame,
				  gfp_t gfp)
{
}

static void quic_frame_new_token_ack(struct sock *sk, struct quic_frame *frame,
				     gfp_t gfp)
{
}

static void quic_frame_stream_ack(struct sock *sk, struct quic_frame *frame,
				  gfp_t gfp)
{
}

static void quic_frame_max_data_ack(struct sock *sk, struct quic_frame *frame,
				    gfp_t gfp)
{
}

static void quic_frame_max_stream_data_ack(struct sock *sk,
					   struct quic_frame *frame, gfp_t gfp)
{
}

static void quic_frame_max_streams_bidi_ack(struct sock *sk,
					    struct quic_frame *frame, gfp_t gfp)
{
}

static void quic_frame_max_streams_uni_ack(struct sock *sk,
					   struct quic_frame *frame, gfp_t gfp)
{
}

static void quic_frame_data_blocked_ack(struct sock *sk,
					struct quic_frame *frame, gfp_t gfp)
{
}

static void quic_frame_stream_data_blocked_ack(struct sock *sk,
					       struct quic_frame *frame,
					       gfp_t gfp)
{
}

static void quic_frame_streams_blocked_bidi_ack(struct sock *sk,
						struct quic_frame *frame,
						gfp_t gfp)
{
}

static void quic_frame_streams_blocked_uni_ack(struct sock *sk,
					       struct quic_frame *frame,
					       gfp_t gfp)
{
}

static void quic_frame_new_conn_id_ack(struct sock *sk,
				       struct quic_frame *frame, gfp_t gfp)
{
}

static void quic_frame_retire_conn_id_ack(struct sock *sk,
					  struct quic_frame *frame, gfp_t gfp)
{
}

static void quic_frame_path_challenge_ack(struct sock *sk,
					  struct quic_frame *frame, gfp_t gfp)
{
}

static void quic_frame_path_response_ack(struct sock *sk,
					 struct quic_frame *frame, gfp_t gfp)
{
}

static void quic_frame_connection_close_ack(struct sock *sk,
					    struct quic_frame *frame, gfp_t gfp)
{
}

static void quic_frame_handshake_done_ack(struct sock *sk,
					  struct quic_frame *frame, gfp_t gfp)
{
}

static void quic_frame_invalid_ack(struct sock *sk, struct quic_frame *frame,
				   gfp_t gfp)
{
}

static void quic_frame_datagram_ack(struct sock *sk, struct quic_frame *frame,
				    gfp_t gfp)
{
}

#define quic_frame_create_and_process_and_ack(type, attr) \
	{ \
		.frame_create	= quic_frame_##type##_create, \
		.frame_process	= quic_frame_##type##_process, \
		.frame_ack	= quic_frame_##type##_ack, \
		.frame_attr	= attr, \
	}

enum quic_frame_attr {
	QUIC_A_1	= BIT(QUIC_CRYPTO_APP),       /* Valid at App */
	QUIC_A_I	= BIT(QUIC_CRYPTO_INITIAL),   /* Valid at Initial */
	QUIC_A_H	= BIT(QUIC_CRYPTO_HANDSHAKE), /* Valid at Handshake */
	QUIC_A_0	= BIT(QUIC_CRYPTO_EARLY),     /* Valid at Early */
	QUIC_A_R	= BIT(QUIC_CRYPTO_MAX),       /* Retransmittable */
	QUIC_A_P	= BIT(QUIC_CRYPTO_MAX + 1),   /* Probing */
	QUIC_A_N	= BIT(QUIC_CRYPTO_MAX + 2),   /* Non-ack-eliciting */
};

/* 12.4. Frames and Frame Types. */
#define QUIC_A_NP_IH01 (QUIC_A_N | QUIC_A_P | QUIC_A_0 | QUIC_A_H | QUIC_A_I | \
			QUIC_A_1)
#define QUIC_A_N__IH01 (QUIC_A_N | QUIC_A_0 | QUIC_A_H | QUIC_A_I | QUIC_A_1)
#define QUIC_A_N____01 (QUIC_A_N | QUIC_A_0 | QUIC_A_1)
#define QUIC_A_N__IH_1 (QUIC_A_N | QUIC_A_H | QUIC_A_I | QUIC_A_1)
#define QUIC_A__PR__01 (QUIC_A_P | QUIC_A_R | QUIC_A_0 | QUIC_A_1)
#define QUIC_A__P___01 (QUIC_A_P | QUIC_A_0 | QUIC_A_1)
#define QUIC_A__P____1 (QUIC_A_P | QUIC_A_1)
#define QUIC_A___RIH_1 (QUIC_A_R | QUIC_A_I | QUIC_A_H | QUIC_A_1)
#define QUIC_A___R__01 (QUIC_A_R | QUIC_A_0 | QUIC_A_1)
#define QUIC_A___R___1 (QUIC_A_R | QUIC_A_1)
#define QUIC_A____IH01 (QUIC_A_0 | QUIC_A_H | QUIC_A_I | QUIC_A_1)
#define QUIC_A______01 (QUIC_A_0 | QUIC_A_1)

static const struct quic_frame_ops quic_frame_ops[QUIC_FRAME_MAX + 1] = {
	/* 0x00 */
	quic_frame_create_and_process_and_ack(padding, QUIC_A_NP_IH01),
	quic_frame_create_and_process_and_ack(ping, QUIC_A____IH01),
	quic_frame_create_and_process_and_ack(ack, QUIC_A_N__IH_1),
	quic_frame_create_and_process_and_ack(ack, QUIC_A_N__IH_1),
	quic_frame_create_and_process_and_ack(reset_stream, QUIC_A___R__01),
	quic_frame_create_and_process_and_ack(stop_sending, QUIC_A___R__01),
	quic_frame_create_and_process_and_ack(crypto, QUIC_A___RIH_1),
	quic_frame_create_and_process_and_ack(new_token, QUIC_A___R___1),
	quic_frame_create_and_process_and_ack(stream, QUIC_A___R__01),
	quic_frame_create_and_process_and_ack(stream, QUIC_A___R__01),
	quic_frame_create_and_process_and_ack(stream, QUIC_A___R__01),
	quic_frame_create_and_process_and_ack(stream, QUIC_A___R__01),
	quic_frame_create_and_process_and_ack(stream, QUIC_A___R__01),
	quic_frame_create_and_process_and_ack(stream, QUIC_A___R__01),
	quic_frame_create_and_process_and_ack(stream, QUIC_A___R__01),
	quic_frame_create_and_process_and_ack(stream, QUIC_A___R__01),
	/* 0x10 */
	quic_frame_create_and_process_and_ack(max_data, QUIC_A___R__01),
	quic_frame_create_and_process_and_ack(max_stream_data, QUIC_A___R__01),
	quic_frame_create_and_process_and_ack(max_streams_bidi, QUIC_A___R__01),
	quic_frame_create_and_process_and_ack(max_streams_uni, QUIC_A___R__01),
	quic_frame_create_and_process_and_ack(data_blocked, QUIC_A___R__01),
	quic_frame_create_and_process_and_ack(stream_data_blocked,
					      QUIC_A___R__01),
	quic_frame_create_and_process_and_ack(streams_blocked_bidi,
					      QUIC_A___R__01),
	quic_frame_create_and_process_and_ack(streams_blocked_uni,
					      QUIC_A___R__01),
	quic_frame_create_and_process_and_ack(new_conn_id, QUIC_A__PR__01),
	quic_frame_create_and_process_and_ack(retire_conn_id, QUIC_A___R__01),
	quic_frame_create_and_process_and_ack(path_challenge, QUIC_A__P___01),
	quic_frame_create_and_process_and_ack(path_response, QUIC_A__P____1),
	quic_frame_create_and_process_and_ack(connection_close, QUIC_A_N__IH01),
	quic_frame_create_and_process_and_ack(connection_close, QUIC_A_N____01),
	quic_frame_create_and_process_and_ack(handshake_done, QUIC_A___R___1),
	quic_frame_create_and_process_and_ack(invalid, 0),
	/* 0x20 */
	quic_frame_create_and_process_and_ack(invalid, 0),
	quic_frame_create_and_process_and_ack(invalid, 0),
	quic_frame_create_and_process_and_ack(invalid, 0),
	quic_frame_create_and_process_and_ack(invalid, 0),
	quic_frame_create_and_process_and_ack(invalid, 0),
	quic_frame_create_and_process_and_ack(invalid, 0),
	quic_frame_create_and_process_and_ack(invalid, 0),
	quic_frame_create_and_process_and_ack(invalid, 0),
	quic_frame_create_and_process_and_ack(invalid, 0),
	quic_frame_create_and_process_and_ack(invalid, 0),
	quic_frame_create_and_process_and_ack(invalid, 0),
	quic_frame_create_and_process_and_ack(invalid, 0),
	quic_frame_create_and_process_and_ack(invalid, 0),
	quic_frame_create_and_process_and_ack(invalid, 0),
	quic_frame_create_and_process_and_ack(invalid, 0),
	quic_frame_create_and_process_and_ack(invalid, 0),
	/* 0x30 */
	quic_frame_create_and_process_and_ack(datagram, QUIC_A______01),
	quic_frame_create_and_process_and_ack(datagram, QUIC_A______01),
};

static bool quic_frame_level_valid(u8 level, u8 type)
{
	return !!(quic_frame_ops[type].frame_attr & BIT(level));
}

static bool quic_frame_non_probe(u8 type)
{
	return !(quic_frame_ops[type].frame_attr & QUIC_A_P);
}

bool quic_frame_retransmittable(u8 type)
{
	return !!(quic_frame_ops[type].frame_attr & QUIC_A_R);
}

bool quic_frame_ack_eliciting(u8 type)
{
	return !(quic_frame_ops[type].frame_attr & QUIC_A_N);
}

void quic_frame_ack(struct sock *sk, struct quic_frame *frame, gfp_t gfp)
{
	quic_frame_ops[frame->type].frame_ack(sk, frame, gfp);
	quic_frame_put(frame);
}

int quic_frame_process(struct sock *sk, struct quic_frame *frame, gfp_t gfp)
{
	struct quic_skb_cb *cb = QUIC_SKB_CB(frame->skb);
	struct quic_packet *packet = quic_packet(sk);
	u8 type, level = frame->level;
	u64 value;
	int ret;

	if (!frame->len) {
		/* rfc9000#section-12.4:
		 *
		 * An endpoint MUST treat receipt of a packet containing no
		 * frames as a connection error of type PROTOCOL_VIOLATION.
		 */
		cb->errcode = QUIC_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
		return -EINVAL;
	}

	while (frame->len > 0) {
		ret = frame->len;
		if (!quic_get_var(&frame->data, &ret, &value))
			return -EINVAL;
		frame->len = ret;

		if (value > QUIC_FRAME_MAX ||
		    !quic_frame_ops[value].frame_attr) {
			pr_debug("%s: unknown frame, type: %llx, level: %d\n",
				 __func__, value, level);
			/* rfc9000#section-12.4:
			 *
			 * An endpoint MUST treat the receipt of a frame of
			 * unknown type as a connection error of type
			 * FRAME_ENCODING_ERROR.
			 */
			cb->errcode = QUIC_TRANSPORT_ERROR_FRAME_ENCODING;
			return -EPROTONOSUPPORT;
		}
		type = (u8)value;
		if (!quic_frame_level_valid(level, type)) {
			pr_debug("%s: invalid frame, type: %x, level: %d\n",
				 __func__, type, level);
			/* An endpoint MUST treat receipt of a frame in a
			 * packet type that is not permitted as a connection
			 * error of type PROTOCOL_VIOLATION.
			 */
			cb->errcode = QUIC_TRANSPORT_ERROR_PROTOCOL_VIOLATION;
			return -EINVAL;
		}
		ret = quic_frame_ops[type].frame_process(sk, frame, type, gfp);
		if (ret < 0) {
			pr_debug("%s: failed, type: %x, level: %d, err: %d\n",
				 __func__, type, level, ret);
			cb->errframe = type;
			cb->errcode = frame->errcode;
			return ret;
		}
		pr_debug("%s: done, type: %x, level: %d\n", __func__, type,
			 level);
		if (quic_frame_ack_eliciting(type)) {
			packet->ack_eliciting = 1;
			/* Require immediate ACKs for non-crypto, non-stream or
			 * stream-FIN frames.
			 */
			if (!quic_frame_crypto(type) &&
			    (!quic_frame_stream(type) ||
			     (type & QUIC_STREAM_BIT_FIN)))
				packet->ack_immediate = 1;
		}
		if (quic_frame_non_probe(type))
			packet->non_probing = 1;
		if (quic_frame_sack(type))
			packet->has_sack = 1;

		frame->data += ret;
		frame->len -= ret;
	}
	return 0;
}

struct quic_frame *quic_frame_create(struct sock *sk, u8 type, void *data,
				     gfp_t gfp)
{
	struct quic_frame *frame;

	if (type > QUIC_FRAME_MAX)
		return ERR_PTR(-EINVAL);
	frame = quic_frame_ops[type].frame_create(sk, data, type, gfp);
	if (!frame) {
		pr_debug("%s: failed, type: %x\n", __func__, type);
		return ERR_PTR(-ENOMEM);
	}
	INIT_LIST_HEAD(&frame->list);
	if (!frame->type)
		frame->type = type;
	pr_debug("%s: done, type: %x, len: %u\n", __func__, type, frame->len);
	return frame;
}

struct quic_frame *quic_frame_alloc(u32 size, u8 *data, gfp_t gfp)
{
	struct quic_frame *frame;

	frame = kmem_cache_zalloc(quic_frame_cachep, gfp);
	if (!frame)
		return NULL;
	if (data) {
		frame->data = data;
		goto out;
	}
	frame->data = kmalloc(size, gfp);
	if (!frame->data) {
		kmem_cache_free(quic_frame_cachep, frame);
		return NULL;
	}
out:
	refcount_set(&frame->refcnt, 1);
	frame->offset = -1;
	frame->len = (u16)size;
	frame->dlen = frame->len;
	return frame;
}

static void quic_frame_free(struct quic_frame *frame)
{
	struct quic_frame_frag *frag, *next;

	/* Handle RX stream/crypto/dgram frames. Use !frame->type to detect RX,
	 * since frame->skb shares a union with frame->flist, used only on TX.
	 */
	if (!frame->type && frame->skb) {
		kfree_skb(frame->skb);
		goto out;
	}

	for (frag = frame->flist; frag; frag = next) {
		next = frag->next;
		kfree(frag);
	}
	kfree(frame->data);
out:
	kmem_cache_free(quic_frame_cachep, frame);
}

struct quic_frame *quic_frame_get(struct quic_frame *frame)
{
	refcount_inc(&frame->refcnt);
	return frame;
}

void quic_frame_put(struct quic_frame *frame)
{
	if (refcount_dec_and_test(&frame->refcnt))
		quic_frame_free(frame);
}

int quic_frame_stream_append(struct sock *sk, struct quic_frame *frame,
			     struct quic_msginfo *info, bool pack)
{
	return -1;
}
