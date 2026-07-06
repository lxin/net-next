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

#include "socket.h"

/* Return true a frame can not be transmitted based on congestion control and
 * Anti-Amplification.
 */
static bool quic_outq_limit_check(struct sock *sk, struct quic_frame *frame)
{
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_packet *packet = quic_packet(sk);
	struct quic_outqueue *outq = quic_outq(sk);
	u32 len;

	/* If in single-packet mode, allow only one packet to transmit. */
	if (outq->single && outq->count)
		return true;

	/* Enforce congestion control for ack-eliciting frames except PING. */
	if (!outq->single && quic_frame_ack_eliciting(frame->type) &&
	    !quic_frame_ping(frame->type)) {
		len = packet->len + frame->len;
		if (outq->inflight + len > outq->window)
			return true;
	}

	/* rfc9000#section-21.1.1.1: Anti-amplification limit for server before
	 * path validation.
	 */
	if (quic_is_serv(sk) && !paths->validated) {
		len = packet->len + frame->len + frame->padding;
		if (paths->ampl_sndlen + len > paths->ampl_rcvlen * 3) {
			paths->blocked = 1;
			return true;
		}
	}

	return false;
}

/* Flush any appended frames or coalesced/bundled packets. */
static int quic_outq_transmit_flush(struct sock *sk, gfp_t gfp)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_outqueue *outq = quic_outq(sk);
	int count = outq->count;

	outq->count = 0;
	if (!quic_packet_empty(packet) && !quic_packet_create_and_xmit(sk, gfp))
		count++;
	quic_packet_flush(sk);

	return count;
}

/* Transmits control frames at a given encryption level (Initial, Handshake,
 * 1-RTT)).
 */
static void quic_outq_transmit_ctrl(struct sock *sk, u8 level, gfp_t gfp)
{
	struct quic_pnspace *space = quic_pnspace(sk, level);
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_frame *frame, *next;
	struct list_head *head;

	if (!quic_crypto(sk, level)->send_ready)
		return;

	if (space->need_sack) {
		/* Transmit SACK (ACK for crypto space) first if needed. */
		if (!quic_outq_transmit_frame(sk, QUIC_FRAME_ACK, &level,
					      space->sack_path, true, gfp))
			space->need_sack = 0;
	}

	head = &outq->control_list;
	list_for_each_entry_safe(frame, next, head, list) {
		if (!frame->level && level) /* Initial/Handshake before 1-RTT */
			break;
		if (frame->level != level)
			continue;
		if (quic_packet_config(sk, frame->level, frame->path))
			break;
		if (quic_outq_limit_check(sk, frame))
			break;
		if (quic_packet_tail(sk, frame))
			continue; /* Frame appended. */
		/* Flush already appended frames before processing this one. */
		if (quic_packet_create_and_xmit(sk, gfp))
			break;
		outq->count++;
		next = frame; /* Re-append this frame. */
	}
}

/* Transmit application datagrams (QUIC DATAGRAM frames). */
static void quic_outq_transmit_dgram(struct sock *sk, gfp_t gfp)
{
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_frame *frame, *next;
	struct list_head *head;

	if (!quic_crypto(sk, outq->data_level)->send_ready)
		return;

	head = &outq->datagram_list;
	list_for_each_entry_safe(frame, next, head, list) {
		if (quic_packet_config(sk, outq->data_level, frame->path))
			break;
		if (quic_outq_limit_check(sk, frame))
			break;
		if (quic_packet_tail(sk, frame))
			continue;
		if (quic_packet_create_and_xmit(sk, gfp))
			break;
		outq->count++;
		next = frame;
	}
}

/* Applies stream and connection-level flow control. Returns 1 if blocked, 0
 * otherwise.  Send a STREAM_DATA_BLOCKED or DATA_BLOCKED frame if blocked and
 * sndblock is true.
 */
int quic_outq_flow_control(struct sock *sk, struct quic_stream *stream,
			   u16 bytes, bool sndblock)
{
	struct quic_outqueue *outq = quic_outq(sk);
	u8 frame, blocked = 0, transmit = 0;
	gfp_t gfp = GFP_KERNEL;

	/* Check connection-level flow control. */
	if (outq->bytes + bytes <= outq->max_bytes)
		goto stream_out;

	/* Send a DATA_BLOCKED frame only after the previous one is ACKed, and
	 * max_bytes has been updated via a received MAX_DATA frame.
	 */
	if (!outq->data_blocked && outq->last_max_bytes < outq->max_bytes) {
		frame = QUIC_FRAME_DATA_BLOCKED;
		if (!sndblock ||
		    !quic_outq_transmit_frame(sk, frame, outq, 0, true, gfp)) {
			outq->last_max_bytes = outq->max_bytes;
			outq->data_blocked = 1;
			transmit = sndblock;
		}
	}
	blocked = 1;

stream_out:
	/* Check stream-level flow control. */
	if (stream->send.bytes + bytes <= stream->send.max_bytes)
		goto out;

	/* Send a STREAM_DATA_BLOCKED frame only after the previous one is
	 * ACKed, and stream->send.max_bytes has been updated via a received
	 * MAX_STREAM_DATA frame.
	 */
	if (!stream->send.data_blocked &&
	    stream->send.last_max_bytes < stream->send.max_bytes) {
		frame = QUIC_FRAME_STREAM_DATA_BLOCKED;
		if (!sndblock ||
		    !quic_outq_transmit_frame(sk, frame, stream, 0, true,
					      gfp)) {
			stream->send.last_max_bytes = stream->send.max_bytes;
			stream->send.data_blocked = 1;
			transmit = sndblock;
		}
	}
	blocked = 1;

out:
	if (transmit)
		quic_outq_transmit(sk, gfp);

	return blocked;
}

/* Returns available writable space considering stream limits if stream is set,
 * otherwise connection limits.
 */
u64 quic_outq_wspace(struct sock *sk, struct quic_stream *stream)
{
	struct quic_outqueue *outq = quic_outq(sk);
	u64 len;

	if (outq->max_bytes <= outq->bytes)
		return 0;
	len = outq->max_bytes - outq->bytes;

	if (!stream)
		return len;

	if (stream->send.max_bytes <= stream->send.bytes)
		return 0;
	len = min_t(u64, len, stream->send.max_bytes - stream->send.bytes);
	len = min_t(u64, len, sk_stream_wspace(sk));

	return len;
}

/* Applies pacing and Nagle’s algorithm. Returns true if sending should be
 * delayed, false if immediate send.
 */
static bool quic_outq_delay_check(struct sock *sk, u8 level, bool nodelay)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_outqueue *outq = quic_outq(sk);
	u64 pacing_time;

	if (level || outq->close_pending)
		return false; /* No delay for early data/closing conn */

	pacing_time = quic_cong(sk)->pacing_time;
	if (pacing_time > ktime_get_ns()) { /* Delay data TX in PACE timer. */
		quic_timer_start(sk, QUIC_TIMER_PACE, pacing_time);
		return true;
	}

	if (nodelay) /* If the frame is not the last of a sendmsg. */
		return false;
	/* If there’s already data queued in the packet, send immediately. */
	if (!quic_packet_empty(packet))
		return false;
	/* If Nagle is disabled via config or no data is in flight, and
	 * MSG_MORE isn't set, allow immediate send.
	 */
	if ((outq->stream_data_nodelay || !outq->inflight) &&
	    !outq->force_delay)
		return false;
	/* If enough stream data is available to build a full-sized packet,
	 * send immediately.
	 */
	if (outq->stream_list_len >= quic_packet_max_payload(packet))
		return false;
	return true; /* Otherwise, delay sending to coalesce more data. */
}

/* Sends stream data frames. */
static void quic_outq_transmit_stream(struct sock *sk, gfp_t gfp)
{
	struct quic_pnspace *space = quic_pnspace(sk, QUIC_CRYPTO_APP);
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_frame *frame, *next;
	struct list_head *head;
	bool sent = false;

	/* Although frame->level is always App, stream data may need to be sent
	 * at App or Early level depending on key availability. Use
	 * outq->data_level to select the level.
	 */
	if (!quic_crypto(sk, outq->data_level)->send_ready)
		return;

	head = &outq->stream_list;
	list_for_each_entry_safe(frame, next, head, list) {
		if (quic_packet_config(sk, outq->data_level, frame->path))
			break;
		if (quic_outq_limit_check(sk, frame))
			break;
		if (quic_outq_delay_check(sk, outq->data_level, frame->nodelay))
			break;
		if (quic_packet_tail(sk, frame)) {
			sent = true;
			outq->stream_list_len -= frame->len;
			continue;
		}
		if (quic_packet_create_and_xmit(sk, gfp))
			break;
		outq->count++;
		next = frame;
	}

	/* Bundle an ACK frame if there is a pending delayed ACK. */
	if (sent && space->sack_pending) {
		space->need_sack = 1;
		space->sack_path = 0;
		space->sack_pending = 0;
		quic_outq_transmit_ctrl(sk, QUIC_CRYPTO_APP, gfp);
	}
}

/* Sends all pending frames from outqueue. Returns number of packets sent. */
int quic_outq_transmit(struct sock *sk, gfp_t gfp)
{
	quic_outq_transmit_ctrl(sk, QUIC_CRYPTO_INITIAL, gfp);
	quic_outq_transmit_ctrl(sk, QUIC_CRYPTO_HANDSHAKE, gfp);
	quic_outq_transmit_ctrl(sk, QUIC_CRYPTO_APP, gfp);

	quic_outq_transmit_dgram(sk, gfp);
	quic_outq_transmit_stream(sk, gfp);

	return quic_outq_transmit_flush(sk, gfp);
}

/* Frees socket send memory resources. */
static void quic_outq_data_wfree(int len, struct sock *sk)
{
	if (!len)
		return;

	WARN_ON_ONCE(refcount_sub_and_test(len, &sk->sk_wmem_alloc));
	sk_wmem_queued_add(sk, -len);
	sk_mem_uncharge(sk, len);

	if (sk_stream_wspace(sk) > 0)
		sk->sk_write_space(sk);
}

/* Charges memory to socket for new frame. */
static void quic_outq_data_wcharge(int len, struct sock *sk)
{
	if (!len)
		return;

	refcount_add(len, &sk->sk_wmem_alloc);
	sk_wmem_queued_add(sk, len);
	sk_mem_charge(sk, len);
}

static void quic_outq_wcharge(struct quic_frame *frame, struct sock *sk)
{
	quic_outq_data_wcharge(quic_frame_size(frame), sk);
}

/* Appends data to an existing stream frame at the tail of the stream_list if
 * possible.
 */
int quic_outq_stream_append(struct sock *sk, struct quic_msginfo *info,
			    bool pack)
{
	struct quic_stream_table *streams = quic_streams(sk);
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_stream *stream = info->stream;
	struct quic_frame *frame;
	struct list_head *head;
	int len, bytes;

	head = &outq->stream_list;
	if (list_empty(head))
		return -ENOENT;
	/* Append only if it's the same stream, the frame is last of a sendmsg
	 * (i.e., !nodelay) and it hasn't been transmitted yet (number < 0).
	 */
	frame = list_last_entry(head, struct quic_frame, list);
	if (frame->stream != stream || frame->nodelay || frame->number >= 0)
		return -EINVAL;

	len = frame->len;
	bytes = quic_frame_stream_append(sk, frame, info, pack);
	/* If append failed or this was a size probe, return immediately. */
	if (bytes < 0 || !pack)
		return bytes;

	/* If FIN bit is now set and the stream was in SEND state, mark it SENT
	 * and clear active_stream_id if it matches.
	 */
	if (frame->type & QUIC_STREAM_BIT_FIN &&
	    stream->send.state == QUIC_STREAM_SEND_STATE_SEND) {
		if (streams->send.active_stream_id == stream->id)
			streams->send.active_stream_id = -1;
		stream->send.state = QUIC_STREAM_SEND_STATE_SENT;
	}

	/* Update accounting. */
	stream->send.bytes += bytes;

	outq->bytes += bytes;
	outq->stream_list_len += (frame->len - len);
	outq->unsent_bytes += bytes;
	quic_outq_data_wcharge(bytes, sk);

	return bytes;
}

/* Queues a stream frame at the tail of the stream list and optionally triggers
 * transmission.
 */
void quic_outq_stream_tail(struct sock *sk, struct quic_frame *frame, bool cork)
{
	struct quic_stream_table *streams = quic_streams(sk);
	struct quic_stream *stream = frame->stream;
	struct quic_outqueue *outq = quic_outq(sk);

	/* rfc9000#section-3.1:
	 *
	 * Sending the first STREAM or STREAM_DATA_BLOCKED frame causes a
	 * sending part of a stream to enter the "Send" state.
	 *
	 * After the application indicates that all stream data has been sent
	 * and a STREAM frame containing the FIN bit is sent, the sending part
	 * of the stream enters the "Data Sent" state.
	 */
	if (stream->send.state == QUIC_STREAM_SEND_STATE_READY)
		stream->send.state = QUIC_STREAM_SEND_STATE_SEND;

	if (frame->type & QUIC_STREAM_BIT_FIN &&
	    stream->send.state == QUIC_STREAM_SEND_STATE_SEND) {
		/* Clear active_stream_id if it matches the finished stream. */
		if (streams->send.active_stream_id == stream->id)
			streams->send.active_stream_id = -1;
		stream->send.state = QUIC_STREAM_SEND_STATE_SENT;
	}

	/* Update accounting. */
	stream->send.frags++;
	stream->send.bytes += frame->bytes;

	outq->bytes += frame->bytes;
	outq->stream_list_len += frame->len;
	outq->unsent_bytes += frame->bytes;
	quic_outq_wcharge(frame, sk);

	list_add_tail(&frame->list, &outq->stream_list);
	if (!cork) /* If not corked, trigger transmission immediately. */
		quic_outq_transmit(sk, GFP_KERNEL);
}

/* Queues a datagram frame at the tail of the datagram list and optionally
 * transmits.
 */
void quic_outq_dgram_tail(struct sock *sk, struct quic_frame *frame, bool cork)
{
	struct quic_outqueue *outq = quic_outq(sk);

	outq->unsent_bytes += frame->bytes;
	quic_outq_wcharge(frame, sk);
	list_add_tail(&frame->list, &outq->datagram_list);
	if (!cork)
		quic_outq_transmit(sk, GFP_KERNEL);
}

/* Map level 0 (QUIC_CRYPTO_APP) to lowest priority. */
static u8 quic_level_prio(u8 level)
{
	return level ?: QUIC_CRYPTO_MAX;
}

/* Queues a control frame in control_list in correct order and optionally
 * transmits.
 */
void quic_outq_ctrl_tail(struct sock *sk, struct quic_frame *frame, bool cork,
			 gfp_t gfp)
{
	struct quic_outqueue *outq = quic_outq(sk);
	struct list_head *head;
	struct quic_frame *pos;
	u8 f_prio, p_prio;

	head = &quic_outq(sk)->control_list;
	/* Insert frame in priority order:
	 *
	 *   Initial (level == 1) > Handshake (level == 2) > Application
	 *   (level == 0); At same level: Non-ack-eliciting > Ack-eliciting.
	 */
	f_prio = quic_level_prio(frame->level);
	list_for_each_entry(pos, head, list) {
		p_prio = quic_level_prio(pos->level);

		if (f_prio > p_prio)
			continue;
		if (f_prio < p_prio) {
			head = &pos->list;
			break;
		}
		if (quic_frame_ack_eliciting(frame->type) <
		    quic_frame_ack_eliciting(pos->type)) {
			head = &pos->list;
			break;
		}
	}

	outq->unsent_bytes += frame->bytes;
	quic_outq_wcharge(frame, sk);
	list_add_tail(&frame->list, head);
	if (!cork)
		quic_outq_transmit(sk, gfp);
}

/* Transmit a probe packet (PING frame with padding) to assist with PLPMTUD. */
void quic_outq_transmit_probe(struct sock *sk, gfp_t gfp)
{
	struct quic_pnspace *space = quic_pnspace(sk, QUIC_CRYPTO_APP);
	u32 taglen = quic_packet_taglen(quic_packet(sk));
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_probeinfo info = {};
	u32 pathmtu;

	if (!quic_is_established(sk))
		return;

	/* Set probe packet size and encryption level. */
	info.size = paths->pl.probe_size;
	info.level = QUIC_CRYPTO_APP;
	/* Save the packet number used for confirming the probe via ACK. */
	pathmtu = quic_path_pl_send(paths, space->next_pn);
	if (pathmtu) /* Pathmtu may drop if probe failures exceeds. */
		quic_packet_mss_update(sk, pathmtu + taglen);
	if (quic_outq_transmit_frame(sk, QUIC_FRAME_PING, &info, 0, false, gfp))
		paths->pl.number = 0;

	/* Restart the PLPMTUD timer for future probes if this one fails. */
	quic_timer_reset(sk, QUIC_TIMER_PMTU, paths->plpmtud_interval);
}

/* Queue and send a CONNECTION_CLOSE frame to terminate the connection. */
void quic_outq_transmit_close(struct sock *sk, u8 type, u32 errcode, u8 level)
{
	struct quic_outqueue *outq = quic_outq(sk);
	gfp_t gfp = GFP_KERNEL;

	outq->close_errcode = errcode;
	outq->close_frame = type;

	quic_outq_transmit_frame(sk, QUIC_FRAME_CONNECTION_CLOSE, &level, 0,
				 false, gfp);
	quic_set_state(sk, QUIC_SS_CLOSED);
}

/* Send an application-level CONNECTION_CLOSE frame, typically called by
 * close() or shutdown().
 */
void quic_outq_transmit_app_close(struct sock *sk)
{
	struct quic_outqueue *outq = quic_outq(sk);
	gfp_t gfp = GFP_KERNEL;
	u8 type, level;

	if (quic_is_closed(sk) || quic_is_listen(sk))
		return;

	if (quic_is_establishing(sk)) {
		/* Handshake in progress: send close in INITIAL packets. */
		level = QUIC_CRYPTO_INITIAL;
		type = QUIC_FRAME_CONNECTION_CLOSE;
		outq->close_errcode = QUIC_TRANSPORT_ERROR_APPLICATION;
		goto out;
	}

	level = QUIC_CRYPTO_APP;
	type = QUIC_FRAME_CONNECTION_CLOSE_APP;
	outq->close_pending = 1;
	quic_outq_transmit(sk, gfp); /* Flush before sending close frame. */

out:
	quic_outq_transmit_frame(sk, type, &level, 0, false, gfp);
}

/* Initiate probing of an alternative QUIC path to support path migration. */
int quic_outq_probe_path_alt(struct sock *sk, bool cork, gfp_t gfp)
{
	struct quic_conn_id_set *id_set = quic_dest(sk);
	struct quic_path_group *paths = quic_paths(sk);
	u64 number, timeout;
	int err;

	/* Try to select an alternate connection ID for the new path. */
	if (!quic_conn_id_select_alt(id_set, false)) {
		/* If a probe is already pending, we cannot proceed. */
		if (quic_path_alt_state(paths, QUIC_PATH_ALT_PENDING))
			return -EINVAL;

		/* No alternate ID available; retire the old connection ID and
		 * request a new connection ID to prepare for migration.
		 */
		number = quic_conn_id_first_number(id_set);
		err = quic_outq_transmit_frame(sk,
					       QUIC_FRAME_RETIRE_CONNECTION_ID,
					       &number, 0, cork, gfp);
		if (err)
			return err;

		/* Mark path migration as pending. */
		quic_path_set_alt_state(paths, QUIC_PATH_ALT_PENDING);
		return 0;
	}

	/* Alternate connection ID selected; start active probing. */
	quic_path_set_alt_state(paths, QUIC_PATH_ALT_PROBING);
	paths->ecn_probes = 0;
	quic_set_sk_ecn(sk, 0);
	/* Send PATH_CHALLENGE frame on the new path and reset path timer. */
	quic_outq_transmit_frame(sk, QUIC_FRAME_PATH_CHALLENGE, NULL, 1, cork,
				 gfp);

	timeout = max_t(u32, quic_cong(sk)->pto * 2, QUIC_MIN_PATH_TIMEOUT);
	quic_timer_reset(sk, QUIC_TIMER_PATH, timeout);
	return 0;
}

/* Create and queue a QUIC control frame for transmission.
 *
 * This function creates a new quic_frame with the given type and data, sets
 * the path for the frame, and appends it to the control frame queue.
 */
int quic_outq_transmit_frame(struct sock *sk, u8 type, void *data, u8 path,
			     bool cork, gfp_t gfp)
{
	struct quic_frame *frame;

	frame = quic_frame_create(sk, type, data, gfp);
	if (IS_ERR(frame))
		return PTR_ERR(frame);

	frame->path = path;
	quic_outq_ctrl_tail(sk, frame, cork, gfp);
	return 0;
}

/* Send NEW_CONNECTION_ID frames.
 *
 * This function sends multiple NEW_CONNECTION_ID frames for any connection IDs
 * with sequence numbers between (last known + 1) and (max_count + prior - 1).
 */
int quic_outq_transmit_new_conn_id(struct sock *sk, u64 prior, u8 path,
				   bool cork, gfp_t gfp)
{
	struct quic_conn_id_set *id_set = quic_source(sk);
	u64 max, seqno;
	int err;

	/* Compute the maximum sequence number to send. */
	max = id_set->max_count + prior;
	for (seqno = quic_conn_id_last_number(id_set) + 1; seqno < max;
	     seqno++) {
		err = quic_outq_transmit_frame(sk, QUIC_FRAME_NEW_CONNECTION_ID,
					       &prior, path, true, gfp);
		if (err)
			return err;
	}
	if (!cork)
		quic_outq_transmit(sk, gfp);
	return 0;
}

/* Send RETIRE_CONNECTION_ID frames.
 *
 * This function queues RETIRE_CONNECTION_ID frames for all sequence numbers
 * from the first known ID up to the specified prior sequence number.
 */
int quic_outq_transmit_retire_conn_id(struct sock *sk, u64 prior, u8 path,
				      bool cork, gfp_t gfp)
{
	struct quic_conn_id_set *id_set = quic_dest(sk);
	u64 seqno;
	int err;

	for (seqno = quic_conn_id_first_number(id_set); seqno < prior;
	     seqno++) {
		err = quic_outq_transmit_frame(sk,
					       QUIC_FRAME_RETIRE_CONNECTION_ID,
					       &seqno, path, true, gfp);
		if (err)
			return err;
	}
	if (!cork)
		quic_outq_transmit(sk, gfp);
	return 0;
}

/* Configure outqueue from transport parameters. */
void quic_outq_set_param(struct sock *sk, struct quic_transport_param *p)
{
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_cong *cong = quic_cong(sk);

	if (!p->remote)
		return;

	outq->disable_compatible_version = !!p->disable_compatible_version;
	outq->disable_1rtt_encryption = !!p->disable_1rtt_encryption;
	outq->max_datagram_frame_size = p->max_datagram_frame_size;
	outq->max_udp_payload_size = p->max_udp_payload_size;
	outq->ack_delay_exponent = p->ack_delay_exponent;
	outq->max_idle_timeout = p->max_idle_timeout;
	outq->grease_quic_bit = !!p->grease_quic_bit;
	outq->stateless_reset = !!p->stateless_reset;
	outq->max_ack_delay = p->max_ack_delay;
	outq->max_data = p->max_data;

	outq->max_bytes = outq->max_data;
	cong->max_window = min_t(u64, outq->max_data, S32_MAX / 4);
	cong->max_ack_delay = outq->max_ack_delay;

	/* max_datagram_frame_size or max_udp_payload_size changed; reset
	 * socket route so quic_packet_route() recalculates MSS.
	 */
	__sk_dst_reset(sk);
	quic_packet_route(sk);
}

/* Populate transport parameters from outqueue. */
void quic_outq_get_param(struct sock *sk, struct quic_transport_param *p)
{
	struct quic_outqueue *outq = quic_outq(sk);

	if (!p->remote)
		return;

	p->disable_compatible_version = outq->disable_compatible_version;
	p->disable_1rtt_encryption = outq->disable_1rtt_encryption;
	p->max_datagram_frame_size = outq->max_datagram_frame_size;
	p->max_udp_payload_size = outq->max_udp_payload_size;
	p->ack_delay_exponent = outq->ack_delay_exponent;
	p->max_idle_timeout = outq->max_idle_timeout;
	p->grease_quic_bit = outq->grease_quic_bit;
	p->stateless_reset = outq->stateless_reset;
	p->max_ack_delay = outq->max_ack_delay;
	p->max_data = outq->max_data;
}

void quic_outq_init(struct sock *sk)
{
	struct quic_outqueue *outq = quic_outq(sk);

	INIT_LIST_HEAD(&outq->stream_list);
	INIT_LIST_HEAD(&outq->control_list);
	INIT_LIST_HEAD(&outq->datagram_list);
}

/* Purge frames from an outq list: only those for a given stream, or all if
 * stream is NULL.
 */
void quic_outq_list_purge(struct sock *sk, struct list_head *head,
			  struct quic_stream *stream)
{
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_frame *frame, *next;
	int bytes = 0;

	list_for_each_entry_safe(frame, next, head, list) {
		if (stream && frame->stream != stream)
			continue;

		if (head == &outq->stream_list)
			outq->stream_list_len -= frame->len;
		if (frame->number < 0)
			outq->unsent_bytes -= frame->bytes;

		bytes += quic_frame_size(frame);
		list_del_init(&frame->list);
		quic_frame_put(frame);
	}
	quic_outq_data_wfree(bytes, sk);
}

void quic_outq_free(struct sock *sk)
{
	struct quic_outqueue *outq = quic_outq(sk);

	quic_outq_list_purge(sk, &outq->datagram_list, NULL);
	quic_outq_list_purge(sk, &outq->control_list, NULL);
	quic_outq_list_purge(sk, &outq->stream_list, NULL);
	kfree(outq->close_phrase);
	outq->close_phrase = NULL;
}
