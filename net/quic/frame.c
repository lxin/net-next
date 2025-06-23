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

static struct quic_frame *quic_frame_ack_create(struct sock *sk, void *data, u8 type)
{
	return NULL;
}

static struct quic_frame *quic_frame_ping_create(struct sock *sk, void *data, u8 type)
{
	return NULL;
}

static struct quic_frame *quic_frame_padding_create(struct sock *sk, void *data, u8 type)
{
	return NULL;
}

static struct quic_frame *quic_frame_new_token_create(struct sock *sk, void *data, u8 type)
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

static struct quic_frame *quic_frame_stream_create(struct sock *sk, void *data, u8 type)
{
	return NULL;
}

static struct quic_frame *quic_frame_handshake_done_create(struct sock *sk, void *data, u8 type)
{
	return NULL;
}

static struct quic_frame *quic_frame_crypto_create(struct sock *sk, void *data, u8 type)
{
	return NULL;
}

static struct quic_frame *quic_frame_retire_conn_id_create(struct sock *sk, void *data, u8 type)
{
	return NULL;
}

static struct quic_frame *quic_frame_new_conn_id_create(struct sock *sk, void *data, u8 type)
{
	return NULL;
}

static struct quic_frame *quic_frame_path_response_create(struct sock *sk, void *data, u8 type)
{
	return NULL;
}

static struct quic_frame *quic_frame_path_challenge_create(struct sock *sk, void *data, u8 type)
{
	return NULL;
}

static struct quic_frame *quic_frame_reset_stream_create(struct sock *sk, void *data, u8 type)
{
	return NULL;
}

static struct quic_frame *quic_frame_stop_sending_create(struct sock *sk, void *data, u8 type)
{
	return NULL;
}

static struct quic_frame *quic_frame_max_data_create(struct sock *sk, void *data, u8 type)
{
	return NULL;
}

static struct quic_frame *quic_frame_max_stream_data_create(struct sock *sk, void *data, u8 type)
{
	return NULL;
}

static struct quic_frame *quic_frame_max_streams_uni_create(struct sock *sk, void *data, u8 type)
{
	return NULL;
}

static struct quic_frame *quic_frame_max_streams_bidi_create(struct sock *sk, void *data, u8 type)
{
	return NULL;
}

static struct quic_frame *quic_frame_connection_close_create(struct sock *sk, void *data, u8 type)
{
	return NULL;
}

static struct quic_frame *quic_frame_data_blocked_create(struct sock *sk, void *data, u8 type)
{
	return NULL;
}

static struct quic_frame *quic_frame_stream_data_blocked_create(struct sock *sk,
								void *data, u8 type)
{
	return NULL;
}

static struct quic_frame *quic_frame_streams_blocked_uni_create(struct sock *sk,
								void *data, u8 type)
{
	return NULL;
}

static struct quic_frame *quic_frame_streams_blocked_bidi_create(struct sock *sk,
								 void *data, u8 type)
{
	return NULL;
}

static int quic_frame_crypto_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	return -EOPNOTSUPP;
}

static int quic_frame_stream_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	return -EOPNOTSUPP;
}

static int quic_frame_ack_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	return -EOPNOTSUPP;
}

static int quic_frame_new_conn_id_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	return -EOPNOTSUPP;
}

static int quic_frame_retire_conn_id_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	return -EOPNOTSUPP;
}

static int quic_frame_new_token_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	return -EOPNOTSUPP;
}

static int quic_frame_handshake_done_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	return -EOPNOTSUPP;
}

static int quic_frame_padding_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	return -EOPNOTSUPP;
}

static int quic_frame_ping_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	return -EOPNOTSUPP;
}

static int quic_frame_path_challenge_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	return -EOPNOTSUPP;
}

static int quic_frame_reset_stream_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	return -EOPNOTSUPP;
}

static int quic_frame_stop_sending_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	return -EOPNOTSUPP;
}

static int quic_frame_max_data_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	return -EOPNOTSUPP;
}

static int quic_frame_max_stream_data_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	return -EOPNOTSUPP;
}

static int quic_frame_max_streams_uni_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	return -EOPNOTSUPP;
}

static int quic_frame_max_streams_bidi_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	return -EOPNOTSUPP;
}

static int quic_frame_connection_close_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	return -EOPNOTSUPP;
}

static int quic_frame_data_blocked_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	return -EOPNOTSUPP;
}

static int quic_frame_stream_data_blocked_process(struct sock *sk, struct quic_frame *frame,
						  u8 type)
{
	return -EOPNOTSUPP;
}

static int quic_frame_streams_blocked_uni_process(struct sock *sk, struct quic_frame *frame,
						  u8 type)
{
	return -EOPNOTSUPP;
}

static int quic_frame_streams_blocked_bidi_process(struct sock *sk, struct quic_frame *frame,
						   u8 type)
{
	return -EOPNOTSUPP;
}

static int quic_frame_path_response_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	return -EOPNOTSUPP;
}

static struct quic_frame *quic_frame_invalid_create(struct sock *sk, void *data, u8 type)
{
	return NULL;
}

static struct quic_frame *quic_frame_datagram_create(struct sock *sk, void *data, u8 type)
{
	return NULL;
}

static int quic_frame_invalid_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	return -EOPNOTSUPP;
}

static int quic_frame_datagram_process(struct sock *sk, struct quic_frame *frame, u8 type)
{
	return -EOPNOTSUPP;
}

static void quic_frame_padding_ack(struct sock *sk, struct quic_frame *frame)
{
}

static void quic_frame_ping_ack(struct sock *sk, struct quic_frame *frame)
{
}

static void quic_frame_ack_ack(struct sock *sk, struct quic_frame *frame)
{
}

static void quic_frame_reset_stream_ack(struct sock *sk, struct quic_frame *frame)
{
}

static void quic_frame_stop_sending_ack(struct sock *sk, struct quic_frame *frame)
{
}

static void quic_frame_crypto_ack(struct sock *sk, struct quic_frame *frame)
{
}

static void quic_frame_new_token_ack(struct sock *sk, struct quic_frame *frame)
{
}

static void quic_frame_stream_ack(struct sock *sk, struct quic_frame *frame)
{
}

static void quic_frame_max_data_ack(struct sock *sk, struct quic_frame *frame)
{
}

static void quic_frame_max_stream_data_ack(struct sock *sk, struct quic_frame *frame)
{
}

static void quic_frame_max_streams_bidi_ack(struct sock *sk, struct quic_frame *frame)
{
}

static void quic_frame_max_streams_uni_ack(struct sock *sk, struct quic_frame *frame)
{
}

static void quic_frame_data_blocked_ack(struct sock *sk, struct quic_frame *frame)
{
}

static void quic_frame_stream_data_blocked_ack(struct sock *sk, struct quic_frame *frame)
{
}

static void quic_frame_streams_blocked_bidi_ack(struct sock *sk, struct quic_frame *frame)
{
}

static void quic_frame_streams_blocked_uni_ack(struct sock *sk, struct quic_frame *frame)
{
}

static void quic_frame_new_conn_id_ack(struct sock *sk, struct quic_frame *frame)
{
}

static void quic_frame_retire_conn_id_ack(struct sock *sk, struct quic_frame *frame)
{
}

static void quic_frame_path_challenge_ack(struct sock *sk, struct quic_frame *frame)
{
}

static void quic_frame_path_response_ack(struct sock *sk, struct quic_frame *frame)
{
}

static void quic_frame_connection_close_ack(struct sock *sk, struct quic_frame *frame)
{
}

static void quic_frame_handshake_done_ack(struct sock *sk, struct quic_frame *frame)
{
}

static void quic_frame_invalid_ack(struct sock *sk, struct quic_frame *frame)
{
}

static void quic_frame_datagram_ack(struct sock *sk, struct quic_frame *frame)
{
}

#define quic_frame_create_and_process_and_ack(type, eliciting) \
	{ \
		.frame_create	= quic_frame_##type##_create, \
		.frame_process	= quic_frame_##type##_process, \
		.frame_ack	= quic_frame_##type##_ack, \
		.ack_eliciting	= eliciting \
	}

static struct quic_frame_ops quic_frame_ops[QUIC_FRAME_MAX + 1] = {
	quic_frame_create_and_process_and_ack(padding, 0), /* 0x00 */
	quic_frame_create_and_process_and_ack(ping, 1),
	quic_frame_create_and_process_and_ack(ack, 0),
	quic_frame_create_and_process_and_ack(ack, 0), /* ack_ecn */
	quic_frame_create_and_process_and_ack(reset_stream, 1),
	quic_frame_create_and_process_and_ack(stop_sending, 1),
	quic_frame_create_and_process_and_ack(crypto, 1),
	quic_frame_create_and_process_and_ack(new_token, 1),
	quic_frame_create_and_process_and_ack(stream, 1),
	quic_frame_create_and_process_and_ack(stream, 1),
	quic_frame_create_and_process_and_ack(stream, 1),
	quic_frame_create_and_process_and_ack(stream, 1),
	quic_frame_create_and_process_and_ack(stream, 1),
	quic_frame_create_and_process_and_ack(stream, 1),
	quic_frame_create_and_process_and_ack(stream, 1),
	quic_frame_create_and_process_and_ack(stream, 1),
	quic_frame_create_and_process_and_ack(max_data, 1), /* 0x10 */
	quic_frame_create_and_process_and_ack(max_stream_data, 1),
	quic_frame_create_and_process_and_ack(max_streams_bidi, 1),
	quic_frame_create_and_process_and_ack(max_streams_uni, 1),
	quic_frame_create_and_process_and_ack(data_blocked, 1),
	quic_frame_create_and_process_and_ack(stream_data_blocked, 1),
	quic_frame_create_and_process_and_ack(streams_blocked_bidi, 1),
	quic_frame_create_and_process_and_ack(streams_blocked_uni, 1),
	quic_frame_create_and_process_and_ack(new_conn_id, 1),
	quic_frame_create_and_process_and_ack(retire_conn_id, 1),
	quic_frame_create_and_process_and_ack(path_challenge, 0),
	quic_frame_create_and_process_and_ack(path_response, 0),
	quic_frame_create_and_process_and_ack(connection_close, 0),
	quic_frame_create_and_process_and_ack(connection_close, 0),
	quic_frame_create_and_process_and_ack(handshake_done, 1),
	quic_frame_create_and_process_and_ack(invalid, 0),
	quic_frame_create_and_process_and_ack(invalid, 0), /* 0x20 */
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
	quic_frame_create_and_process_and_ack(datagram, 1), /* 0x30 */
	quic_frame_create_and_process_and_ack(datagram, 1),
};

void quic_frame_ack(struct sock *sk, struct quic_frame *frame)
{
	quic_frame_ops[frame->type].frame_ack(sk, frame);

	list_del_init(&frame->list);
	frame->transmitted = 0;
	quic_frame_put(frame);
}

int quic_frame_process(struct sock *sk, struct quic_frame *frame)
{
	u8 type, level = frame->level;
	int ret;

	while (frame->len > 0) {
		type = *frame->data++;
		frame->len--;

		if (type > QUIC_FRAME_MAX) {
			pr_debug("%s: unsupported frame, type: %x, level: %d\n",
				 __func__, type, level);
			return -EPROTONOSUPPORT;
		} else if (quic_frame_level_check(level, type)) {
			pr_debug("%s: invalid frame, type: %x, level: %d\n",
				 __func__, type, level);
			return -EINVAL;
		}
		ret = quic_frame_ops[type].frame_process(sk, frame, type);
		if (ret < 0) {
			pr_debug("%s: failed, type: %x, level: %d, err: %d\n",
				 __func__, type, level, ret);
			return ret;
		}
		pr_debug("%s: done, type: %x, level: %d\n", __func__, type, level);

		frame->data += ret;
		frame->len -= ret;
	}
	return 0;
}

struct quic_frame *quic_frame_create(struct sock *sk, u8 type, void *data)
{
	struct quic_frame *frame;

	if (type > QUIC_FRAME_MAX)
		return NULL;
	frame = quic_frame_ops[type].frame_create(sk, data, type);
	if (!frame) {
		pr_debug("%s: failed, type: %x\n", __func__, type);
		return NULL;
	}
	INIT_LIST_HEAD(&frame->list);
	if (!frame->type)
		frame->type = type;
	frame->ack_eliciting = quic_frame_ops[type].ack_eliciting;
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
	frame->size = frame->len;
	return frame;
}

static void quic_frame_free(struct quic_frame *frame)
{
	struct quic_frame_frag *frag, *next;

	if (!frame->type && frame->skb) { /* RX path frame with skb. */
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
			     struct quic_msginfo *info, u8 pack)
{
	return -1;
}
