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

/* rfc9000#section-19.3:
 *
 * ACK or ACK_ECN Frame {
 *  Type (i) = 0x02..0x03,
 *  Largest Acknowledged (i),
 *  ACK Delay (i),
 *  ACK Range Count (i),
 *  First ACK Range (i),
 *  ACK Range (..) ...,
 *  [ECN Counts (..)],
 * }
 *
 * ACK Range {
 *   Gap (i),
 *   ACK Range Length (i),
 * }
 *
 * ECN Counts {
 *   ECT0 Count (i),
 *   ECT1 Count (i),
 *   ECN-CE Count (i),
 * }
 *
 * Receivers send ACK or ACK_ECN frames to inform senders of packets they have
 * received and processed. The ACK frame contains one or more ACK Ranges. ACK
 * Ranges identify acknowledged packets. If ACK_ECN frames also contain the
 * cumulative count of QUIC packets with associated ECN marks received on the
 * connection up until this point.
 */
static struct quic_frame *
quic_frame_ack_create(struct sock *sk, void *data, u8 type, gfp_t gfp)
{
	struct quic_gap_ack_block gabs[QUIC_PN_MAP_MAX_GABS];
	u64 largest, smallest, range, delay, *ecn_count;
	struct quic_outqueue *outq = quic_outq(sk);
	u8 *p, level = *((u8 *)data);
	struct quic_pnspace *space;
	u32 frame_len, num_gabs, i;
	struct quic_frame *frame;

	space = quic_pnspace(sk, level);
	/* If ECN counts are present, use ACK_ECN frame type. */
	type += quic_pnspace_has_ecn_local(space);
	/* Collect gap-based ACK blocks from the PN space. */
	num_gabs = quic_pnspace_num_gabs(space, gabs);

	/* Determine the Largest Acknowledged and First ACK Range. */
	largest = space->max_pn_seen;
	smallest = space->min_pn_seen;
	if (num_gabs)
		smallest = space->base_pn + gabs[num_gabs - 1].end;
	/* rfc9000#section-19.3.1: smallest = largest - ack_range. */
	range = largest - smallest;
	/* Calculate ACK Delay, adjusted by the ACK delay exponent. */
	delay = quic_ktime_get_us() - space->max_pn_time;
	delay >>= outq->ack_delay_exponent;

	/* Estimate the maximum frame length:
	 *   type + 4 * varints + ranges + ECN Counts.
	 */
	frame_len = 1 + quic_var_len(largest) + quic_var_len(delay) +
		    quic_var_len(num_gabs) + quic_var_len(range) +
		    quic_var_len(QUIC_PN_MAP_SIZE) * 2 * num_gabs +
		    sizeof(*ecn_count) * QUIC_ECN_MAX;
	frame = quic_frame_alloc(frame_len, NULL, gfp);
	if (!frame)
		return ERR_PTR(-ENOMEM);
	p = quic_put_var(frame->data, type);
	p = quic_put_var(p, largest); /* Largest Acknowledged. */
	p = quic_put_var(p, delay); /* ACK Delay. */
	p = quic_put_var(p, num_gabs); /* ACK Count. */
	p = quic_put_var(p, range); /* First ACK Range. */

	if (num_gabs) { /* Encode additional ACK Ranges and Gaps if present. */
		for (i = num_gabs - 1; i > 0; i--) {
			/* Gap. */
			p = quic_put_var(p, gabs[i].end - gabs[i].start);
			/* ACK Range Length. */
			p = quic_put_var(p,
					 gabs[i].start - gabs[i - 1].end - 2);
		}
		/* Final gap and range. */
		p = quic_put_var(p, gabs[0].end - gabs[0].start); /* Gap. */
		largest = gabs[0].start - 1 + space->base_pn - 1;
		range = largest - space->min_pn_seen;
		p = quic_put_var(p, range); /* ACK Range Length. */
	}
	if (type == QUIC_FRAME_ACK_ECN) {
		ecn_count = space->ecn_count[QUIC_ECN_LOCAL];
		p = quic_put_var(p, ecn_count[QUIC_ECN_ECT0]); /* ECT0 Count. */
		p = quic_put_var(p, ecn_count[QUIC_ECN_ECT1]); /* ECT1 Count. */
		p = quic_put_var(p, ecn_count[QUIC_ECN_CE]); /* ECN-CE Count. */
	}
	/* Finalize frame metadata. */
	frame->type = type;
	frame->len = (u16)(p - frame->data);
	frame->dlen = frame->len;
	frame->level = level;

	return frame;
}

/* rfc9000#section-19.2:
 *
 * PING Frame {
 *   Type (i) = 0x01,
 * }
 *
 * Endpoints can use PING frames to verify that their peers are still alive or
 * to check reachability to the peer.
 *
 * It is also used for PMTUD probing. When probe size is provided, it fills the
 * rest of the frame with zeros and sets the padding flag.
 */
static struct quic_frame *
quic_frame_ping_create(struct sock *sk, void *data, u8 type, gfp_t gfp)
{
	struct quic_probeinfo *info = data;
	u8 *p, buf[QUIC_FRAME_BUF_SMALL];
	struct quic_frame *frame;
	u32 overhead, frame_len;

	p = quic_put_var(buf, type);
	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, gfp);
	if (!frame)
		return ERR_PTR(-ENOMEM);
	frame->level = info->level;
	quic_put_data(frame->data, buf, frame_len);

	/* If a probe size is specified and larger than the overhead, request
	 * padding to reach that total size.
	 */
	overhead = quic_packet_overhead(sk, info->level, 0);
	if (info->size > overhead + frame_len)
		frame->padding = info->size - overhead - frame_len;
	return frame;
}

/* rfc9000#section-19.1:
 *
 * PADDING Frame {
 *   Type (i) = 0x00,
 * }
 *
 * A PADDING frame (type=0x00) has no semantic value. PADDING frames can be
 * used to increase the size of a packet.
 */
static struct quic_frame *
quic_frame_padding_create(struct sock *sk, void *data, u8 type, gfp_t gfp)
{
	struct quic_frame *frame;
	u32 *frame_len = data;

	frame = quic_frame_alloc(*frame_len + 1, NULL, gfp);
	if (!frame)
		return ERR_PTR(-ENOMEM);
	quic_put_var(frame->data, type);
	memset(frame->data + 1, 0, *frame_len);

	return frame;
}

/* rfc9000#section-19.7:
 *
 *
 * NEW_TOKEN Frame {
 *   Type (i) = 0x07,
 *   Token Length (i),
 *   Token (..),
 * }
 *
 * The NEW_TOKEN frame is used by servers to provide address validation tokens
 * to clients.  These tokens can be used by clients to skip address validation
 * in future connections.
 */
static struct quic_frame *
quic_frame_new_token_create(struct sock *sk, void *data, u8 type, gfp_t gfp)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
	struct quic_conn_id_set *id_set = quic_source(sk);
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_outqueue *outq = quic_outq(sk);
	u8 *p, buf[QUIC_FRAME_BUF_LARGE];
	struct quic_frame *frame;
	u32 tlen;
	int err;

	/* Write token flags into buffer: QUIC_TOKEN_FLAG_REGULAR means regular
	 * token.
	 */
	quic_put_int(buf, QUIC_TOKEN_FLAG_REGULAR, 1);
	/* Generate token into buf; includes client's address and conn ID. */
	err = quic_crypto_generate_token(crypto, quic_path_daddr(paths, 0),
					 sizeof(union quic_addr),
					 quic_conn_id_active(id_set),
					 buf, &tlen);
	if (err)
		return ERR_PTR(err);

	frame = quic_frame_alloc(tlen + 1 + quic_var_len(tlen), NULL, gfp);
	if (!frame)
		return ERR_PTR(-ENOMEM);
	p = quic_put_var(frame->data, type);
	p = quic_put_var(p, tlen);
	p = quic_put_data(p, buf, tlen);
	frame->len = (u16)(p - frame->data);
	frame->dlen = frame->len;
	outq->token_pending = 1; /* Mark token pending until it gets ACKed. */

	return frame;
}

static struct quic_frame_frag *quic_frame_frag_alloc(u16 len)
{
	struct quic_frame_frag *frag;

	frag = kmalloc(sizeof(*frag) + len, GFP_KERNEL);
	if (frag) {
		frag->dlen = len;
		frag->next = NULL;
	}

	return frag;
}

/* rfc9000#section-19.8:
 *
 * STREAM Frame {
 *  Type (i) = 0x08..0x0f,
 *  Stream ID (i),
 *  [Offset (i)],
 *  [Length (i)],
 *  Stream Data (..),
 * }
 *
 * STREAM frames implicitly create a stream and carry stream data. The Type
 * field in the STREAM frame takes the form 0b00001XXX (or the set of values
 * from 0x08 to 0x0f). The three low-order bits of the frame type determine the
 * fields that are present in the frame: The OFF bit (0x04); The LEN bit
 * (0x02); The FIN bit (0x01).
 */
static struct quic_frame *
quic_frame_stream_create(struct sock *sk, void *data, u8 type, gfp_t gfp)
{
	u32 msg_len, max_frame_len, hlen = 1;
	struct quic_msginfo *info = data;
	struct quic_frame_frag *frag;
	struct quic_stream *stream;
	struct quic_frame *frame;
	u8 *p, nodelay = 0;
	u64 wspace;

	stream = info->stream;
	/* Estimate header length: type (1 byte) + varint stream ID. */
	hlen += quic_var_len(stream->id);
	/* If there is a non-zero offset, include it and set OFF bit. */
	if (stream->send.bytes) {
		type |= QUIC_STREAM_BIT_OFF;
		hlen += quic_var_len(stream->send.bytes); /* varint Offset. */
	}
	/* For simplicity, always include length; set LEN bit. */
	type |= QUIC_STREAM_BIT_LEN;
	/* Reserve max varint length in case more data is appended later. */
	hlen += quic_var_len(QUIC_MAX_UDP_PAYLOAD);

	max_frame_len = quic_packet_max_payload(quic_packet(sk)); /* MSS. */
	msg_len = iov_iter_count(info->msg); /* Total user message length. */
	wspace = quic_outq_wspace(sk, stream); /* Flow control limit. */

	/* Trim msg_len to respect flow control and MSS constraints. */
	if ((u64)msg_len <= wspace) { /* All data fits in flow control limit. */
		if (msg_len <= max_frame_len - hlen) { /* Fits in MSS. */
			/* If fully fits, include FIN bit if requested. */
			if (info->flags & MSG_QUIC_STREAM_FIN)
				type |= QUIC_STREAM_BIT_FIN;
		} else { /* Limit to MSS and mark as nodelay. */
			nodelay = 1;
			msg_len = max_frame_len - hlen;
		}
	} else { /* Limit to flow control limit. */
		msg_len = wspace;
		if (msg_len > max_frame_len - hlen) {
			/* Limit to MSS and mark as nodelay. */
			nodelay = 1;
			msg_len = max_frame_len - hlen;
		}
	}

	frame = quic_frame_alloc(hlen, NULL, gfp);
	if (!frame)
		return ERR_PTR(-ENOMEM);
	frame->stream = stream;

	if (msg_len) { /* Allocate and attach frame fragment for the payload. */
		frag = quic_frame_frag_alloc(msg_len);
		if (!frag) {
			quic_frame_put(frame);
			return ERR_PTR(-ENOMEM);
		}
		/* Copy user data into the frame fragment. */
		if (!copy_from_iter_full(frag->data, msg_len, info->msg)) {
			quic_frame_put(frame);
			kfree(frag);
			return ERR_PTR(-EFAULT);
		}
		frame->flist = frag;
	}

	/* Encode STREAM frame header. */
	p = quic_put_var(frame->data, type);
	p = quic_put_var(p, stream->id);
	if (type & QUIC_STREAM_BIT_OFF)
		p = quic_put_var(p, stream->send.bytes);
	p = quic_put_var(p, msg_len);

	/* Finalize frame metadata. */
	frame->type = type;
	frame->dlen = (u16)(p - frame->data);
	frame->bytes = (u16)msg_len;
	frame->len = frame->dlen + frame->bytes;
	frame->nodelay = nodelay;
	frame->stream_fin = !!(type & QUIC_STREAM_BIT_FIN);

	return frame;
}

/* rfc9000#section-19.20:
 *
 * HANDSHAKE_DONE Frame {
 *   Type (i) = 0x1e,
 * }
 *
 * The server uses a HANDSHAKE_DONE frame (type=0x1e) to signal confirmation of
 * the handshake to the client.
 */
static struct quic_frame *
quic_frame_handshake_done_create(struct sock *sk, void *data, u8 type,
				 gfp_t gfp)
{
	u8 *p, buf[QUIC_FRAME_BUF_SMALL];
	struct quic_frame *frame;
	u32 frame_len;

	p = quic_put_var(buf, type);
	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, gfp);
	if (!frame)
		return ERR_PTR(-ENOMEM);
	quic_put_data(frame->data, buf, frame_len);

	return frame;
}

/* rfc9000#section-19.6:
 *
 * CRYPTO Frame {
 *   Type (i) = 0x06,
 *   Offset (i),
 *   Length (i),
 *   Crypto Data (..),
 * }
 *
 * A CRYPTO frame (type=0x06) is used to transmit cryptographic handshake
 * messages. It can be sent in all packet types except 0-RTT. The CRYPTO frame
 * offers the cryptographic protocol an in-order stream of bytes. CRYPTO frames
 * are functionally identical to STREAM frames, except that they do not bear a
 * stream identifier.
 */
static struct quic_frame *
quic_frame_crypto_create(struct sock *sk, void *data, u8 type, gfp_t gfp)
{
	u32 msg_len, max_frame_len, wspace, hlen = 1;
	struct quic_msginfo *info = data;
	struct quic_crypto *crypto;
	struct quic_frame *frame;
	u64 offset;
	u8 *p;

	max_frame_len = quic_packet_max_payload(quic_packet(sk)); /* MSS. */
	/* Reserve space for a possible retry token in Client Initial. */
	if (info->level == QUIC_CRYPTO_INITIAL && !quic_is_serv(sk))
		max_frame_len -= (U8_MAX + 1);
	crypto = quic_crypto(sk, info->level);
	msg_len = iov_iter_count(info->msg);
	wspace = sk_stream_wspace(sk);

	offset = crypto->send_offset;
	hlen += quic_var_len(offset);
	hlen += quic_var_len(max_frame_len);
	/* Trim msg_len to respect socket sndbuf and MSS constraints. */
	if (msg_len > wspace)
		msg_len = wspace;
	if (msg_len > max_frame_len - hlen)
		msg_len = max_frame_len - hlen;

	frame = quic_frame_alloc(msg_len + hlen, NULL, gfp);
	if (!frame)
		return ERR_PTR(-ENOMEM);
	p = quic_put_var(frame->data, type);
	p = quic_put_var(p, offset);
	p = quic_put_var(p, msg_len);
	if (!copy_from_iter_full(p, msg_len, info->msg)) {
		quic_frame_put(frame);
		return ERR_PTR(-EFAULT);
	}
	p += msg_len;

	frame->bytes = (u16)msg_len;
	frame->len = (u16)(p - frame->data);
	frame->dlen = frame->len;
	frame->level = info->level;

	return frame;
}

/* rfc9000#section-19.16:
 *
 * RETIRE_CONNECTION_ID Frame {
 *   Type (i) = 0x19,
 *   Sequence Number (i),
 * }
 *
 * An endpoint sends a RETIRE_CONNECTION_ID frame (type=0x19) to indicate that
 * it will no longer use a connection ID that was issued by its peer.
 */
static struct quic_frame *
quic_frame_retire_conn_id_create(struct sock *sk, void *data, u8 type,
				 gfp_t gfp)
{
	struct quic_conn_id_set *id_set = quic_dest(sk);
	struct quic_connection_id_info info = {};
	u8 *p, buf[QUIC_FRAME_BUF_SMALL];
	struct quic_conn_id *active;
	struct quic_frame *frame;
	u64 *seqno = data; /* Sequence number to retire. */
	u32 frame_len;

	p = quic_put_var(buf, type);
	p = quic_put_var(p, *seqno);
	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, gfp);
	if (!frame)
		return ERR_PTR(-ENOMEM);
	quic_put_data(frame->data, buf, frame_len);
	/* Remove the specified connection ID from the destination CID set. */
	quic_conn_id_remove(id_set, *seqno);

	/* Notify the QUIC stack that a CID has been retired. */
	info.dest = 1;
	info.prior_to =  quic_conn_id_first_number(id_set);
	active = quic_conn_id_active(id_set);
	info.active = quic_conn_id_number(active);
	quic_inq_event_recv(sk, QUIC_EVENT_CONNECTION_ID, &info, sizeof(info),
			    gfp);

	return frame;
}

/* rfc9000#section-19.15:
 *
 * NEW_CONNECTION_ID Frame {
 *   Type (i) = 0x18,
 *   Sequence Number (i),
 *   Retire Prior To (i),
 *   Length (8),
 *   Connection ID (8..160),
 *   Stateless Reset Token (128),
 * }
 *
 * An endpoint sends a NEW_CONNECTION_ID frame (type=0x18) to provide its peer
 * with alternative connection IDs that can be used to break linkability when
 * migrating connections.
 */
static struct quic_frame *
quic_frame_new_conn_id_create(struct sock *sk, void *data, u8 type, gfp_t gfp)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
	u8 *p, buf[QUIC_FRAME_BUF_LARGE], token[QUIC_CONN_ID_TOKEN_LEN];
	struct quic_conn_id_set *id_set = quic_source(sk);
	u32 frame_len, tlen = QUIC_CONN_ID_TOKEN_LEN;
	struct quic_conn_id scid = {};
	u64 seqno, *prior = data; /* Retire Prior To. */
	struct quic_frame *frame;
	int err;

	/* Compute the next sequence number for the new connection ID. */
	seqno = quic_conn_id_last_number(id_set) + 1;

	p = quic_put_var(buf, type);
	p = quic_put_var(p, seqno);
	p = quic_put_var(p, *prior);
	/* Generate value for the new source connection ID (SCID). */
	quic_conn_id_generate(&scid);
	p = quic_put_var(p, scid.len);
	p = quic_put_data(p, scid.data, scid.len);
	/* rfc9000#section-10.3:
	 *
	 * A stateless reset token is specific to a connection ID. An endpoint
	 * issues a stateless reset token by including the value in the
	 * Stateless Reset Token field of a NEW_CONNECTION_ID frame.
	 */
	err = quic_crypto_derive_secret(crypto, scid.data, scid.len,
					"stateless_reset", token, tlen);
	if (err)
		return ERR_PTR(err);
	p = quic_put_data(p, token, tlen);
	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, gfp);
	if (!frame)
		return ERR_PTR(-ENOMEM);
	quic_put_data(frame->data, buf, frame_len);

	/* Register the new SCID in the connection ID set with the new sequence
	 * number.
	 */
	err = quic_conn_id_add(id_set, &scid, seqno, sk, gfp);
	if (err) {
		quic_frame_put(frame);
		return ERR_PTR(err);
	}

	return frame;
}

/* rfc9000#section-19.18:
 *
 * PATH_RESPONSE Frame {
 *   Type (i) = 0x1b,
 *   Data (64),
 * }
 *
 * A PATH_RESPONSE frame (type=0x1b) is sent in response to a PATH_CHALLENGE
 * frame.
 */
static struct quic_frame *
quic_frame_path_response_create(struct sock *sk, void *data, u8 type, gfp_t gfp)
{
	u8 *p, buf[QUIC_FRAME_BUF_SMALL], *entropy = data;
	struct quic_frame *frame;
	u32 frame_len;

	p = quic_put_var(buf, type);
	p = quic_put_data(p, entropy, QUIC_PATH_ENTROPY_LEN);
	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, gfp);
	if (!frame)
		return ERR_PTR(-ENOMEM);
	quic_put_data(frame->data, buf, frame_len);

	return frame;
}

/* rfc9000#section-19.17:
 *
 * PATH_CHALLENGE Frame {
 *   Type (i) = 0x1a,
 *   Data (64),
 * }
 *
 * Endpoints can use PATH_CHALLENGE frames (type=0x1a) to check reachability to
 * the peer and for path validation during connection migration.
 */
static struct quic_frame *
quic_frame_path_challenge_create(struct sock *sk, void *data, u8 type,
				 gfp_t gfp)
{
	u8 *p, *entropy, buf[QUIC_FRAME_BUF_SMALL];
	struct quic_frame *frame;
	u32 frame_len;

	entropy = quic_paths(sk)->entropy;
	/* Generate new entropy each time. */
	get_random_bytes(entropy, QUIC_PATH_ENTROPY_LEN);

	p = quic_put_var(buf, type);
	p = quic_put_data(p, entropy, QUIC_PATH_ENTROPY_LEN);
	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, gfp);
	if (!frame)
		return ERR_PTR(-ENOMEM);
	quic_put_data(frame->data, buf, frame_len);

	return frame;
}

/* rfc9000#section-19.4:
 *
 * RESET_STREAM Frame {
 *   Type (i) = 0x04,
 *   Stream ID (i),
 *   Application Protocol Error Code (i),
 *   Final Size (i),
 * }
 *
 * An endpoint uses a RESET_STREAM frame (type=0x04) to abruptly terminate the
 * sending part of a stream.
 */
static struct quic_frame *
quic_frame_reset_stream_create(struct sock *sk, void *data, u8 type, gfp_t gfp)
{
	struct quic_stream_table *streams = quic_streams(sk);
	struct quic_errinfo *info = data; /* Error info. */
	u8 *p, buf[QUIC_FRAME_BUF_LARGE];
	struct quic_stream *stream;
	struct quic_frame *frame;
	u32 frame_len;

	stream = quic_stream_find(streams, info->stream_id);
	if (WARN_ON_ONCE(!stream))
		return ERR_PTR(-ENOENT);

	p = quic_put_var(buf, type);
	p = quic_put_var(p, info->stream_id);
	p = quic_put_var(p, info->errcode);
	p = quic_put_var(p, stream->send.bytes);
	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, gfp);
	if (!frame)
		return ERR_PTR(-ENOMEM);
	quic_put_data(frame->data, buf, frame_len);
	stream->send.errcode = info->errcode;
	frame->stream = stream;

	/* Clear active stream ID if this stream was active. */
	if (streams->send.active_stream_id == stream->id)
		streams->send.active_stream_id = -1;

	return frame;
}

/* rfc9000#section-19.5:
 *
 * STOP_SENDING Frame {
 *   Type (i) = 0x05,
 *   Stream ID (i),
 *   Application Protocol Error Code (i),
 * }
 *
 * An endpoint uses a STOP_SENDING frame (type=0x05) to communicate that
 * incoming data is being discarded on receipt per application request.
 * STOP_SENDING requests that a peer cease transmission on a stream.
 */
static struct quic_frame *
quic_frame_stop_sending_create(struct sock *sk, void *data, u8 type, gfp_t gfp)
{
	struct quic_stream_table *streams = quic_streams(sk);
	struct quic_errinfo *info = data; /* Error info. */
	u8 *p, buf[QUIC_FRAME_BUF_SMALL];
	struct quic_stream *stream;
	struct quic_frame *frame;
	u32 frame_len;

	stream = quic_stream_find(streams, info->stream_id);
	if (WARN_ON_ONCE(!stream))
		return ERR_PTR(-ENOENT);

	p = quic_put_var(buf, type);
	p = quic_put_var(p, info->stream_id);
	p = quic_put_var(p, info->errcode);
	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, gfp);
	if (!frame)
		return ERR_PTR(-ENOMEM);
	quic_put_data(frame->data, buf, frame_len);
	stream->recv.stop_sent = 1; /* Mark stop sending request sent. */
	frame->stream = stream;

	return frame;
}

/* rfc9000#section-19.9:
 *
 * MAX_DATA Frame {
 *   Type (i) = 0x10,
 *   Maximum Data (i),
 * }
 *
 * A MAX_DATA frame (type=0x10) is used in flow control to inform the peer of
 * the maximum amount of data that can be sent on the connection as a whole.
 */
static struct quic_frame *
quic_frame_max_data_create(struct sock *sk, void *data, u8 type, gfp_t gfp)
{
	u8 *p, buf[QUIC_FRAME_BUF_SMALL];
	struct quic_inqueue *inq = data;
	struct quic_frame *frame;
	u32 frame_len;

	p = quic_put_var(buf, type);
	p = quic_put_var(p, inq->max_bytes);
	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, gfp);
	if (!frame)
		return ERR_PTR(-ENOMEM);
	quic_put_data(frame->data, buf, frame_len);

	return frame;
}

/* rfc9000#section-19.10:
 *
 * MAX_STREAM_DATA Frame {
 *   Type (i) = 0x11,
 *   Stream ID (i),
 *   Maximum Stream Data (i),
 * }
 *
 * A MAX_STREAM_DATA frame (type=0x11) is used in flow control to inform a peer
 * of the maximum amount of data that can be sent on a stream.
 */
static struct quic_frame *
quic_frame_max_stream_data_create(struct sock *sk, void *data, u8 type,
				  gfp_t gfp)
{
	struct quic_stream *stream = data;
	u8 *p, buf[QUIC_FRAME_BUF_SMALL];
	struct quic_frame *frame;
	u32 frame_len;

	p = quic_put_var(buf, type);
	p = quic_put_var(p, stream->id);
	p = quic_put_var(p, stream->recv.max_bytes);
	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, gfp);
	if (!frame)
		return ERR_PTR(-ENOMEM);
	quic_put_data(frame->data, buf, frame_len);

	return frame;
}

/* rfc9000#section-19.11:
 *
 * MAX_STREAMS (_UNI or _BIDI) Frame {
 *   Type (i) = 0x12..0x13,
 *   Maximum Streams (i),
 * }
 *
 * A MAX_STREAMS frame (type=0x12 or 0x13) informs the peer of the cumulative
 * number of streams of a given type it is permitted to open. A
 * MAX_STREAMS_BIDI frame applies to bidirectional streams, and a
 * MAX_STREAMS_UNI frame applies to unidirectional streams.
 */
static struct quic_frame *
quic_frame_max_streams_uni_create(struct sock *sk, void *data, u8 type,
				  gfp_t gfp)
{
	u8 *p, buf[QUIC_FRAME_BUF_SMALL];
	struct quic_frame *frame;
	u64 *max = data;
	u32 frame_len;

	p = quic_put_var(buf, type);
	p = quic_put_var(p, *max);
	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, gfp);
	if (!frame)
		return ERR_PTR(-ENOMEM);
	quic_put_data(frame->data, buf, frame_len);

	return frame;
}

/* Similar to quic_frame_max_streams_uni_create(). */
static struct quic_frame *
quic_frame_max_streams_bidi_create(struct sock *sk, void *data, u8 type,
				   gfp_t gfp)
{
	u8 *p, buf[QUIC_FRAME_BUF_SMALL];
	struct quic_frame *frame;
	u64 *max = data;
	u32 frame_len;

	p = quic_put_var(buf, type);
	p = quic_put_var(p, *max);
	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, gfp);
	if (!frame)
		return ERR_PTR(-ENOMEM);
	quic_put_data(frame->data, buf, frame_len);

	return frame;
}

/* rfc9000#section-19.19:
 *
 * CONNECTION_CLOSE or CONNECTION_CLOSE_APP Frame {
 *   Type (i) = 0x1c..0x1d,
 *   Error Code (i),
 *   [Frame Type (i)],
 *   Reason Phrase Length (i),
 *   Reason Phrase (..),
 * }
 *
 * An endpoint sends a CONNECTION_CLOSE or CONNECTION_CLOSE_APP frame to notify
 * its peer that the connection is being closed. The CONNECTION_CLOSE frame is
 * used to signal errors at only the QUIC layer, or the absence of errors (with
 * the NO_ERROR code). The CONNECTION_CLOSE_APP is used to signal an error with
 * the application that uses QUIC.
 */
static struct quic_frame *
quic_frame_connection_close_create(struct sock *sk, void *data, u8 type,
				   gfp_t gfp)
{
	u8 *p, buf[QUIC_FRAME_BUF_LARGE], *phrase, *level = data;
	struct quic_outqueue *outq = quic_outq(sk);
	u32 frame_len, phrase_len = 0;
	struct quic_frame *frame;

	p = quic_put_var(buf, type);
	p = quic_put_var(p, outq->close_errcode);

	if (type == QUIC_FRAME_CONNECTION_CLOSE)
		p = quic_put_var(p, outq->close_frame);

	phrase = outq->close_phrase;
	if (phrase)
		phrase_len = strlen(phrase);
	p = quic_put_var(p, phrase_len);
	p = quic_put_data(p, phrase, phrase_len);

	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, gfp);
	if (!frame)
		return ERR_PTR(-ENOMEM);
	if (type == QUIC_FRAME_CONNECTION_CLOSE)
		QUIC_INC_STATS(sock_net(sk), QUIC_MIB_FRM_OUTCLOSES);
	frame->level = *level;
	quic_put_data(frame->data, buf, frame_len);

	pr_debug("%s: level: %d, errcode: %d, frame: %d\n", __func__,
		 frame->level, outq->close_errcode, outq->close_frame);

	return frame;
}

/* rfc9000#section-19.12:
 *
 * DATA_BLOCKED Frame {
 *   Type (i) = 0x14,
 *   Maximum Data (i),
 * }
 *
 * A sender SHOULD send a DATA_BLOCKED frame (type=0x14) when it wishes to send
 * data but is unable to do so due to connection-level flow control.
 */
static struct quic_frame *
quic_frame_data_blocked_create(struct sock *sk, void *data, u8 type, gfp_t gfp)
{
	struct quic_outqueue *outq = data;
	u8 *p, buf[QUIC_FRAME_BUF_SMALL];
	struct quic_frame *frame;
	u32 frame_len;

	p = quic_put_var(buf, type);
	p = quic_put_var(p, outq->max_bytes);
	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, gfp);
	if (!frame)
		return ERR_PTR(-ENOMEM);
	quic_put_data(frame->data, buf, frame_len);

	return frame;
}

/* rfc9000#section-19.13:
 *
 * STREAM_DATA_BLOCKED Frame {
 *   Type (i) = 0x15,
 *   Stream ID (i),
 *   Maximum Stream Data (i),
 * }
 *
 * A sender SHOULD send a STREAM_DATA_BLOCKED frame (type=0x15) when it wishes
 * to send data but is unable to do so due to stream-level flow control. This
 * frame is analogous to DATA_BLOCKED.
 */
static struct quic_frame *
quic_frame_stream_data_blocked_create(struct sock *sk, void *data, u8 type,
				      gfp_t gfp)
{
	struct quic_stream *stream = data;
	u8 *p, buf[QUIC_FRAME_BUF_SMALL];
	struct quic_frame *frame;
	u32 frame_len;

	p = quic_put_var(buf, type);
	p = quic_put_var(p, stream->id);
	p = quic_put_var(p, stream->send.max_bytes);
	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, gfp);
	if (!frame)
		return ERR_PTR(-ENOMEM);
	quic_put_data(frame->data, buf, frame_len);
	frame->stream = stream;

	return frame;
}

/* rfc9000#section-19.14:
 *
 * STREAMS_BLOCKED (_UNI or _BIDI) Frame {
 *   Type (i) = 0x16..0x17,
 *   Maximum Streams (i),
 * }
 *
 * A sender SHOULD send a STREAMS_BLOCKED frame when it wishes to open a stream
 * but is unable to do so due to the maximum stream limit set by its peer. A
 * STREAMS_BLOCKED_BIDI frame is used to indicate reaching the bidirectional
 * stream limit, and a STREAMS_BLOCKED_UNI frame is used to indicate reaching
 * the unidirectional stream limit.
 */
static struct quic_frame *
quic_frame_streams_blocked_uni_create(struct sock *sk, void *data, u8 type,
				      gfp_t gfp)
{
	struct quic_stream_table *streams = quic_streams(sk);
	u8 *p, buf[QUIC_FRAME_BUF_SMALL];
	struct quic_frame *frame;
	s64 *max = data;
	u32 frame_len;

	p = quic_put_var(buf, type);
	p = quic_put_var(p, quic_stream_id_to_streams(*max));
	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, gfp);
	if (!frame)
		return ERR_PTR(-ENOMEM);
	quic_put_data(frame->data, buf, frame_len);
	streams->send.uni_blocked = 1;

	return frame;
}

/* Similar to quic_frame_streams_blocked_uni_create(). */
static struct quic_frame *
quic_frame_streams_blocked_bidi_create(struct sock *sk, void *data, u8 type,
				       gfp_t gfp)
{
	struct quic_stream_table *streams = quic_streams(sk);
	u8 *p, buf[QUIC_FRAME_BUF_SMALL];
	struct quic_frame *frame;
	s64 *max = data;
	u32 frame_len;

	p = quic_put_var(buf, type);
	p = quic_put_var(p, quic_stream_id_to_streams(*max));
	frame_len = (u32)(p - buf);

	frame = quic_frame_alloc(frame_len, NULL, gfp);
	if (!frame)
		return ERR_PTR(-ENOMEM);
	quic_put_data(frame->data, buf, frame_len);
	streams->send.bidi_blocked = 1;

	return frame;
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
	return ERR_PTR(-EINVAL);
}

/* rfc9221#section-4:
 *
 * DATAGRAM or DATAGRAM_LEN Frame {
 *   Type (i) = 0x30..0x31,
 *   [Length (i)],
 *   Datagram Data (..),
 * }
 *
 * DATAGRAM frames are used to transmit application data in an unreliable
 * manner. There is a Length field present in DATAGRAM_LEN Frame.
 */
static struct quic_frame *
quic_frame_datagram_create(struct sock *sk, void *data, u8 type, gfp_t gfp)
{
	u32 msg_len, hlen = 1, frame_len, max_frame_len;
	struct iov_iter *msg = data;
	struct quic_frame *frame;
	u8 *p;

	/* MSS for dgram. */
	max_frame_len = quic_packet_max_payload_dgram(quic_packet(sk));
	hlen += quic_var_len(max_frame_len);

	/* rfc9221#section-5:
	 *
	 * DATAGRAM frames cannot be fragmented; therefore, application
	 * protocols need to handle cases where the maximum datagram size is
	 * limited by other factors.
	 */
	msg_len = iov_iter_count(msg);
	if (msg_len > max_frame_len - hlen)
		return ERR_PTR(-EMSGSIZE);

	frame = quic_frame_alloc(msg_len + hlen, NULL, gfp);
	if (!frame)
		return ERR_PTR(-ENOMEM);

	p = quic_put_var(frame->data, type);
	/* For simplicity, create DATAGRAM_LEN frame with Length encoded. */
	p = quic_put_var(p, msg_len);

	if (!copy_from_iter_full(p, msg_len, msg)) {
		quic_frame_put(frame);
		return ERR_PTR(-EFAULT);
	}
	p += msg_len;
	frame_len = (u32)(p - frame->data);

	frame->bytes = (u16)msg_len;
	frame->len = (u16)frame_len;
	frame->dlen = frame->len;
	frame->dgram = 1;

	return frame;
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
	if (IS_ERR(frame)) {
		pr_debug("%s: failed, type: %x, err: %pe\n", __func__, type,
			 frame);
		return frame;
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

/* Appends stream data to a QUIC frame. */
int quic_frame_stream_append(struct sock *sk, struct quic_frame *frame,
			     struct quic_msginfo *info, bool pack)
{
	struct quic_stream *stream = info->stream;
	u8 *p, type = frame->type, nodelay = 0;
	u32 msg_len, max_frame_len, hlen = 1;
	struct quic_frame_frag *frag, *pos;
	u64 wspace, offset = 0;

	/* Calculate header length:
	 *   frame type + stream ID + (optional) offset + length.
	 */
	hlen += quic_var_len(stream->id);
	offset = stream->send.bytes - frame->bytes;
	if (offset)
		hlen += quic_var_len(offset);
	max_frame_len = quic_packet_max_payload(quic_packet(sk)); /* MSS. */
	hlen += quic_var_len(max_frame_len);
	if (max_frame_len - hlen <= frame->bytes)
		return -EMSGSIZE; /* Not enough space for more payload. */

	/* Trim msg_len to respect flow control and MSS constraints, similar to
	 * quic_frame_stream_create().
	 */
	msg_len = iov_iter_count(info->msg);
	wspace = quic_outq_wspace(sk, stream);
	if ((u64)msg_len <= wspace) {
		if (msg_len <= max_frame_len - hlen - frame->bytes) {
			if (info->flags & MSG_QUIC_STREAM_FIN)
				type |= QUIC_STREAM_BIT_FIN;
		} else {
			nodelay = 1;
			msg_len = max_frame_len - hlen - frame->bytes;
		}
	} else {
		msg_len = wspace;
		if (msg_len > max_frame_len - hlen - frame->bytes) {
			nodelay = 1;
			msg_len = max_frame_len - hlen - frame->bytes;
		}
	}
	if (!pack) /* Only calculating how much to append. */
		return msg_len;

	if (msg_len) { /* Attach data to frame as fragment. */
		frag = quic_frame_frag_alloc(msg_len);
		if (!frag)
			return -ENOMEM;
		if (!copy_from_iter_full(frag->data, msg_len, info->msg)) {
			kfree(frag);
			return -EFAULT;
		}
		if (frame->flist) {
			pos = frame->flist;
			while (pos->next)
				pos = pos->next;
			pos->next = frag;
		} else {
			frame->flist = frag;
		}
	}

	/* Update stream data header and frame fields. */
	p = quic_put_var(frame->data, type);
	p = quic_put_var(p, stream->id);
	if (offset)
		p = quic_put_var(p, offset);
	p = quic_put_var(p, frame->bytes + msg_len);

	frame->type = type;
	frame->dlen = (u16)(p - frame->data);
	frame->bytes += msg_len;
	frame->len = frame->dlen + frame->bytes;
	frame->nodelay = nodelay;
	frame->stream_fin = !!(type & QUIC_STREAM_BIT_FIN);

	return msg_len;
}
