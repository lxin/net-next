// SPDX-License-Identifier: GPL-2.0-or-later
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Packet creation and processing.
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#include "socket.h"

#define QUIC_HLEN		1

#define QUIC_LONG_HLEN(dcid, scid) \
	(QUIC_HLEN + QUIC_VERSION_LEN + 1 + (dcid)->len + 1 + (scid)->len)

#define QUIC_VERSION_NUM	2

/* Supported QUIC versions and their compatible versions. Used for Compatible
 * Version Negotiation in rfc9368#section-2.3.
 */
static u32 quic_versions[QUIC_VERSION_NUM][4] = {
	/* Version,	Compatible Versions */
	{ QUIC_VERSION_V1, QUIC_VERSION_V2, QUIC_VERSION_V1, 0 },
	{ QUIC_VERSION_V2, QUIC_VERSION_V2, QUIC_VERSION_V1, 0 },
};

/* Get the compatible version list for a given QUIC version. */
u32 *quic_packet_compatible_versions(u32 version)
{
	u8 i;

	for (i = 0; i < QUIC_VERSION_NUM; i++)
		if (version == quic_versions[i][0])
			return quic_versions[i];
	return NULL;
}

/* Convert version-specific type to internal standard packet type. */
static u8 quic_packet_version_get_type(u32 version, u8 type)
{
	if (version == QUIC_VERSION_V1)
		return type;

	switch (type) {
	case QUIC_PACKET_INITIAL_V2:
		return QUIC_PACKET_INITIAL;
	case QUIC_PACKET_0RTT_V2:
		return QUIC_PACKET_0RTT;
	case QUIC_PACKET_HANDSHAKE_V2:
		return QUIC_PACKET_HANDSHAKE;
	case QUIC_PACKET_RETRY_V2:
		return QUIC_PACKET_RETRY;
	default:
		return QUIC_PACKET_INVALID;
	}
}

/* Convert internal standard packet type to version-specific type. */
static u8 quic_packet_version_put_type(u32 version, u8 type)
{
	if (version == QUIC_VERSION_V1)
		return type;

	switch (type) {
	case QUIC_PACKET_INITIAL:
		return QUIC_PACKET_INITIAL_V2;
	case QUIC_PACKET_0RTT:
		return QUIC_PACKET_0RTT_V2;
	case QUIC_PACKET_HANDSHAKE:
		return QUIC_PACKET_HANDSHAKE_V2;
	case QUIC_PACKET_RETRY:
		return QUIC_PACKET_RETRY_V2;
	default:
		return QUIC_PACKET_INVALID;
	}
}

/* Extracts a QUIC Connection ID from a buffer in the long header packet. */
static int quic_packet_get_connid(struct quic_conn_id *connid, u8 **pp,
				  u32 *plen)
{
	u64 len;

	if (!quic_get_int(pp, plen, &len, 1) ||
	    len > *plen || len > QUIC_CONN_ID_MAX_LEN)
		return -EINVAL;

	quic_conn_id_update(connid, *pp, len);
	*plen -= len;
	*pp += len;
	return 0;
}

/* Parse QUIC version and connection IDs (DCID and SCID) from a Long header
 * packet buffer.
 */
static int quic_packet_get_long_header(struct quic_conn_id *dcid,
				       struct quic_conn_id *scid, u32 *version,
				       u8 **pp, u32 *plen)
{
	int err;
	u64 v;

	*pp += QUIC_HLEN;
	*plen -= QUIC_HLEN;

	if (!quic_get_int(pp, plen, &v, QUIC_VERSION_LEN))
		return -EINVAL;
	if (version)
		*version = v;

	err = quic_packet_get_connid(dcid, pp, plen);
	if (err)
		return err;
	if (!scid)
		return 0;
	return quic_packet_get_connid(scid, pp, plen);
}

/* Change the QUIC version for the connection.
 *
 * Frees existing initial crypto keys and installs new initial keys compatible
 * with the new version.
 */
static int quic_packet_version_change(struct sock *sk,
				      struct quic_conn_id *dcid, u32 version)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
	int err;

	/* Cannot re-install key while async crypto is in progress. */
	if (unlikely(atomic_read(&crypto->async_pending[0])))
		return -EBUSY;

	if (!crypto->recv_ready)
		return -EINVAL;

	err = quic_crypto_initial_keys_install(crypto, dcid, version,
					       quic_is_serv(sk));
	if (err)
		return err;

	quic_packet(sk)->version = version;
	return 0;
}

/* Extracts a QUIC token from a buffer in the Client Initial packet. */
static int quic_packet_get_token(struct quic_data *token, u8 **pp, u32 *plen)
{
	u64 len;

	if (!quic_get_var(pp, plen, &len) || len > *plen)
		return -EINVAL;
	quic_data(token, *pp, len);
	*plen -= len;
	*pp += len;
	return 0;
}

/* Process PMTU reduction event on a QUIC socket. */
void quic_packet_rcv_err_pmtu(struct sock *sk)
{
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_packet *packet = quic_packet(sk);
	u32 pathmtu, info, taglen;
	struct dst_entry *dst;
	bool reset_timer;

	if (quic_is_closed(sk))
		return;

	info = clamp(paths->mtu_info, QUIC_PATH_MIN_PMTU, QUIC_PATH_MAX_PMTU);
	/* If PLPMTUD is not enabled, update MSS using route and ICMP info. */
	if (!paths->plpmtud_interval) {
		/* Ensure we have a dst cached for update_pmtu().
		 * ICMP errors apply to the main path (path 0). Use
		 * quic_packet_config() to reset dst cache if path changed.
		 */
		if (quic_packet_config(sk, QUIC_CRYPTO_APP, 0))
			return;

		dst = __sk_dst_get(sk);
		if (dst) {
			dst->ops->update_pmtu(dst, sk, NULL, info, true);
			/* Invalidate cached dst. Next quic_packet_route()
			 * during transmission will pick up the updated MTU
			 * from the newly created route exception and call
			 * quic_packet_mss_update().
			 */
			__sk_dst_reset(sk);
		}
		return;
	}
	/* PLPMTUD is enabled: adjust to smaller PMTU, subtract headers and
	 * AEAD tag.  Also notify the QUIC path layer for possible state
	 * changes and probing.
	 */
	packet->level = QUIC_CRYPTO_APP;
	taglen = quic_packet_taglen(packet);
	info = info - packet->hlen - taglen;
	pathmtu = quic_path_pl_toobig(paths, info, &reset_timer);
	if (reset_timer)
		quic_timer_reset(sk, QUIC_TIMER_PMTU, paths->plpmtud_interval);
	if (pathmtu)
		quic_packet_mss_update(sk, pathmtu + taglen);
}

/* Handle ICMP Toobig packet and update QUIC socket path MTU. */
static int quic_packet_rcv_err(struct sock *sk, struct sk_buff *skb)
{
	union quic_addr daddr, saddr;
	u32 info;

	/* ICMP embeds the original outgoing QUIC packet, so saddr/daddr are
	 * reversed compared to incoming packets. Only address-based socket
	 * lookup is possible in this case.
	 */
	quic_get_msg_addrs(skb, &daddr, &saddr);
	sk = quic_sock_lookup(skb, &saddr, &daddr, sk, NULL);
	if (!sk)
		return -ENOENT;

	if (quic_get_mtu_info(skb, &info) || !quic_sk_accept_pmtu(sk, skb)) {
		sock_put(sk);
		return 0;
	}

	/* Success: update socket path MTU info. */
	bh_lock_sock(sk);
	quic_paths(sk)->mtu_info = info;
	if (sock_owned_by_user(sk)) {
		/* Socket locked by userspace. Defer MTU processing via
		 * release_cb. Hold socket reference to prevent it being
		 * freed before deferral.
		 */
		if (!test_and_set_bit(QUIC_MTU_REDUCED_DEFERRED,
				      &sk->sk_tsq_flags))
			sock_hold(sk);
		goto out;
	}
	/* Otherwise, process the MTU reduction now. */
	quic_packet_rcv_err_pmtu(sk);
out:
	bh_unlock_sock(sk);
	sock_put(sk);
	return 1;
}

/* Queue a packet for later processing when sleeping is allowed.
 * Return: non-zero if skb was consumed (queued or dropped), 0 otherwise.
 */
static int quic_packet_deferred_schedule(struct sk_buff *skb)
{
	struct quic_skb_cb *cb = QUIC_SKB_CB(skb);
	struct sock *sk = skb->sk;
	int len = skb->truesize;

	if (cb->backlog)
		return 0;

	if (sk_rmem_alloc_get(sk) + len > sk->sk_rcvbuf ||
	    !__sk_rmem_schedule(sk, len, false)) {
		QUIC_INC_STATS(sock_net(sk), QUIC_MIB_PKT_RCVDROP);
		kfree_skb(skb);
		return -ENOBUFS;
	}
	cb->backlog = 1;
	skb_set_owner_r(skb, sk);
	__skb_queue_tail(&quic_packet(sk)->deferred_list, skb);

	sock_hold(sk);
	if (!queue_work(quic_wq, quic_work(sk)))
		sock_put(sk);
	return 1;
}

#define TLS_MT_CLIENT_HELLO	1
#define TLS_EXT_alpn		16

/*  TLS Client Hello Msg:
 *
 *    uint16 ProtocolVersion;
 *    opaque Random[32];
 *    uint8 CipherSuite[2];
 *
 *    struct {
 *        ExtensionType extension_type;
 *        opaque extension_data<0..2^16-1>;
 *    } Extension;
 *
 *    struct {
 *        ProtocolVersion legacy_version = 0x0303;
 *        Random rand;
 *        opaque legacy_session_id<0..32>;
 *        CipherSuite cipher_suites<2..2^16-2>;
 *        opaque legacy_compression_methods<1..2^8-1>;
 *        Extension extensions<8..2^16-1>;
 *    } ClientHello;
 */

#define TLS_CH_RANDOM_LEN	32
#define TLS_CH_VERSION_LEN	2
#define TLS_MAX_EXTENSIONS	128

/* Decrypt Initial packet and extract ALPN from TLS ClientHello for ALPN-based
 * socket demultiplexing. Marks packet as decrypted (cb->resume = 1) to avoid
 * redundant decryption later.
 */
static int quic_packet_get_alpn(struct sk_buff *skb, struct quic_data *alpn)
{
	struct quic_skb_cb *cb = QUIC_SKB_CB(skb);
	int err, found = 0, exts = 0;
	struct quic_crypto *crypto;
	struct quic_packet *packet;
	struct sock *sk = skb->sk;
	u64 length, offset, type;
	struct net *net;
	u32 len;
	u8 *p;

	/* Install initial keys for decryption. */
	crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
	packet = quic_packet(sk);
	err = quic_crypto_initial_keys_install(crypto, &packet->dcid,
					       packet->version, true);
	if (err)
		return err;
	cb->sync = 1;
	net = sock_net(sk);
	err = quic_crypto_decrypt(crypto, skb, GFP_KERNEL);
	if (err) {
		QUIC_INC_STATS(net, QUIC_MIB_PKT_DECDROP);
		return err;
	}
	QUIC_INC_STATS(net, QUIC_MIB_PKT_DECFASTPATHS);
	cb->resume = 1; /* Mark this packet as already decrypted. */

	err = -EINVAL;
	/* Find the QUIC CRYPTO frame. */
	p = skb->data + cb->number_offset + cb->number_len;
	len = cb->length - cb->number_len - QUIC_TAG_LEN;
	for (; len && !(*p); p++, len--) /* Skip the padding frame. */
		;
	if (!len-- || *p++ != QUIC_FRAME_CRYPTO)
		return 0; /* No CRYPTO frame: skip ALPN demux. */
	if (!quic_get_var(&p, &len, &offset) || offset)
		return 0; /* Fragmented CRYPTO: skip ALPN demux. */
	if (!quic_get_var(&p, &len, &length) || length > (u64)len)
		return err;
	if (len > (u32)length) /* Cap len to crypto frame length. */
		len = length;

	/* Verify handshake message type (ClientHello) and its length. */
	if (!quic_get_int(&p, &len, &type, 1) || type != TLS_MT_CLIENT_HELLO)
		return err;
	if (!quic_get_int(&p, &len, &length, 3) ||
	    len < TLS_CH_RANDOM_LEN + TLS_CH_VERSION_LEN ||
	    length < TLS_CH_RANDOM_LEN + TLS_CH_VERSION_LEN)
		return err;
	if (len > (u32)length) /* Cap len to handshake msg length. */
		len = length;
	/* Skip legacy_version (2 bytes) + random (32 bytes). */
	p += TLS_CH_RANDOM_LEN + TLS_CH_VERSION_LEN;
	len -= TLS_CH_RANDOM_LEN + TLS_CH_VERSION_LEN;
	/* legacy_session_id_len must be zero (QUIC requirement). */
	if (!quic_get_int(&p, &len, &length, 1) || length)
		return err;

	/* Skip cipher_suites (2 bytes length + variable data). */
	if (!quic_get_int(&p, &len, &length, 2) || length > (u64)len)
		return err;
	len -= length;
	p += length;

	/* Skip legacy_compression_methods (1 byte length + variable data). */
	if (!quic_get_int(&p, &len, &length, 1) || length > (u64)len)
		return err;
	len -= length;
	p += length;

	/* Read TLS extensions length (2 bytes). */
	if (!quic_get_int(&p, &len, &length, 2))
		return err;
	if (len > (u32)length) /* Limit len to extensions length if larger. */
		len = length;
	while (len >= 4) { /* Scan extensions for ALPN (TLS_EXT_alpn). */
		if (exts++ >= TLS_MAX_EXTENSIONS)
			return err;
		if (!quic_get_int(&p, &len, &type, 2))
			break;
		if (!quic_get_int(&p, &len, &length, 2))
			break;
		/* Incomplete TLS extensions: skip ALPN demux. */
		if (len < (u32)length)
			return 0;
		if (type == TLS_EXT_alpn) { /* Found ALPN extension. */
			if (length > QUIC_ALPN_MAX_LEN)
				return err;
			len = length;
			found = 1;
			break;
		}
		/* Skip non-ALPN extensions. */
		p += length;
		len -= length;
	}
	if (!found) { /* No ALPN ext: set alpn->len = 0 and alpn->data = p. */
		quic_data(alpn, p, 0);
		return 0;
	}

	/* Parse ALPN protocols list length (2 bytes). */
	if (!quic_get_int(&p, &len, &length, 2) || length > (u64)len)
		return err;
	quic_data(alpn, p, length); /* Store ALPN list in alpn->data. */
	len = length;
	while (len) { /* Validate ALPN protocols list format. */
		if (!quic_get_int(&p, &len, &length, 1) || length > (u64)len) {
			/* Bad ALPN: set alpn->len = 0, alpn->data = NULL. */
			quic_data(alpn, NULL, 0);
			return err;
		}
		len -= length;
		p += length;
	}
	pr_debug("%s: alpn_len: %u\n", __func__, alpn->len);
	return 0;
}

/* Determine the QUIC socket associated with an incoming packet. */
static struct sock *quic_packet_get_sock(struct sk_buff *skb, struct sock *usk)
{
	struct quic_skb_cb *cb = QUIC_SKB_CB(skb);
	struct quic_conn_id dcid = {}, *conn_id;
	struct net *net = sock_net(usk);
	union quic_addr daddr, saddr;
	struct quic_data alpns = {};
	struct sock *sk = NULL;
	u32 len = skb->len;
	u8 *p = skb->data;
	int err;

	if (skb->len < QUIC_HLEN)
		return ERR_PTR(-EINVAL);

	if (quic_hdr(skb)->form == QUIC_PACKET_FORM_SHORT) {
		/* Short header path. */
		if (skb->len < QUIC_HLEN + QUIC_CONN_ID_DEF_LEN)
			return ERR_PTR(-EINVAL);
		/* Fast path: look up QUIC connection by fixed-length DCID
		 * (Currently, only QUIC_CONN_ID_DEF_LEN-length SCIDs are used).
		 */
		conn_id = quic_conn_id_lookup(net, skb->data + QUIC_HLEN,
					      QUIC_CONN_ID_DEF_LEN);
		if (conn_id) {
			cb->seqno = quic_conn_id_number(conn_id);
			return quic_conn_id_sk(conn_id);
		}

		/* Fallback: listener socket lookup
		 * (May be used to send a stateless reset from a listen socket).
		 */
		quic_get_msg_addrs(skb, &daddr, &saddr);
		sk = quic_listen_sock_lookup(skb, &daddr, &saddr, usk, &alpns);
		if (sk)
			return sk;
		/* Final fallback: address-based connection lookup
		 * (May be used to receive a stateless reset).
		 */
		sk = quic_sock_lookup(skb, &daddr, &saddr, usk, NULL);
		if (!sk)
			return ERR_PTR(-ENOENT);
		return sk;
	}

	/* Long header path. */
	err = quic_packet_get_long_header(&dcid, NULL, NULL, &p, &len);
	if (err)
		return ERR_PTR(err);
	/* Fast path: look up QUIC connection by parsed DCID. */
	conn_id = quic_conn_id_lookup(net, dcid.data, dcid.len);
	if (conn_id) {
		cb->seqno = quic_conn_id_number(conn_id);
		return quic_conn_id_sk(conn_id);
	}

	/* Fallback: address + DCID lookup
	 * (May be used for 0-RTT or a follow-up Client Initial packet).
	 */
	quic_get_msg_addrs(skb, &daddr, &saddr);
	sk = quic_sock_lookup(skb, &daddr, &saddr, usk, &dcid);
	if (sk)
		return sk;
	/* Final fallback: listener socket lookup
	 * (Used for receiving the first Client Initial packet).
	 */
	sk = quic_listen_sock_lookup(skb, &daddr, &saddr, usk, &alpns);
	if (!sk)
		return ERR_PTR(-ENOENT);
	return sk;
}

/* Entry point for processing received QUIC packets. */
int quic_packet_rcv(struct sock *sk, struct sk_buff *skb, bool icmp)
{
	struct net *net = sock_net(sk);
	int err;

	if (unlikely(icmp))
		return quic_packet_rcv_err(sk, skb);

	if (skb_linearize(skb)) {
		err = -ENOMEM;
		goto err;
	}

	/* Look up socket from socket or connection IDs hash tables. */
	sk = quic_packet_get_sock(skb, sk);
	if (IS_ERR(sk)) {
		err = PTR_ERR(sk);
		goto err;
	}

	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		/* Socket is busy (owned by user context): queue to backlog. */
		err = sk_add_backlog(sk, skb, READ_ONCE(sk->sk_rcvbuf));
		if (err) {
			bh_unlock_sock(sk);
			sock_put(sk);
			goto err;
		}
		QUIC_INC_STATS(net, QUIC_MIB_PKT_RCVBACKLOGS);
	} else {
		/* Socket not busy: process immediately. */
		QUIC_INC_STATS(net, QUIC_MIB_PKT_RCVFASTPATHS);
		sk->sk_backlog_rcv(sk, skb); /* quic_backlog_rcv(). */
	}
	bh_unlock_sock(sk);
	sock_put(sk);
	return 0;
err:
	pr_debug("%s: failed, len: %u, err: %d\n", __func__, skb->len, err);
	QUIC_INC_STATS(net, QUIC_MIB_PKT_RCVDROP);
	kfree_skb(skb);
	return err;
}

/* rfc9000#section-17.2.5:
 *
 * Retry Packet {
 *   Header Form (1) = 1,
 *   Fixed Bit (1) = 1,
 *   Long Packet Type (2) = 3,
 *   Unused (4),
 *   Version (32),
 *   Destination Connection ID Length (8),
 *   Destination Connection ID (0..160),
 *   Source Connection ID Length (8),
 *   Source Connection ID (0..160),
 *   Retry Token (..),
 *   Retry Integrity Tag (128),
 * }
 *
 * A Retry packet uses a long packet header with a type value of 0x03. It
 * carries an address validation token created by the server. It is used by a
 * server that wishes to perform a retry.
 */
static int quic_packet_retry_create_and_xmit(struct sock *sk)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
	u8 *p, buf[QUIC_FRAME_BUF_LARGE], tag[QUIC_TAG_LEN];
	struct quic_packet *packet = quic_packet(sk);
	union quic_addr *da = &packet->saddr;
	struct quic_conn_id conn_id = {};
	struct quichshdr *hdr;
	struct sk_buff *skb;
	u32 len, tlen, hlen;
	struct flowi fl;
	int err;

	/* Clear routing cache and compute flow route. */
	__sk_dst_reset(sk);
	err = quic_flow_route(sk, da, &packet->daddr, &fl);
	if (err < 0)
		return err;

	/* Write token flags into buffer: QUIC_TOKEN_FLAG_RETRY means retry
	 * token.
	 */
	buf[0] = QUIC_TOKEN_FLAG_RETRY;
	/* Generate retry token using client's address and DCID from client
	 * initial packet.
	 */
	err = quic_crypto_generate_token(crypto, da, sizeof(*da), &packet->dcid,
					 buf, &tlen);
	if (err)
		return err;

	/* Generate new SCID for the Retry packet. */
	quic_conn_id_generate(&conn_id);
	/* Compute total packet length: header + token + integrity tag. */
	len = QUIC_LONG_HLEN(&packet->scid, &conn_id) + tlen + QUIC_TAG_LEN;
	hlen = quic_encap_len(da) + MAX_HEADER;
	skb = alloc_skb(hlen + len, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;
	skb_reserve(skb, (int)(hlen + len));

	/* Build Long Packet header. */
	hdr = skb_push(skb, len);
	hdr->form = QUIC_PACKET_FORM_LONG;
	hdr->fixed = 1;
	hdr->type = quic_packet_version_put_type(packet->version,
						 QUIC_PACKET_RETRY);
	hdr->reserved = 0;
	hdr->pnl = 0;

	/* Write the QUIC version. */
	p = (u8 *)hdr + QUIC_HLEN;
	p = quic_put_int(p, packet->version, QUIC_VERSION_LEN);
	/* Write Destination Connection ID. */
	p = quic_put_int(p, packet->scid.len, 1);
	p = quic_put_data(p, packet->scid.data, packet->scid.len);
	/* Write Source Connection ID. */
	p = quic_put_int(p, conn_id.len, 1);
	p = quic_put_data(p, conn_id.data, conn_id.len);
	/* Write Retry Token. */
	p = quic_put_data(p, buf, tlen);
	/* Generate and write Retry Integrity Tag.*/
	err = quic_crypto_get_retry_tag(crypto, skb, &packet->dcid,
					packet->version, tag);
	if (err) {
		kfree_skb(skb);
		return err;
	}
	quic_put_data(p, tag, QUIC_TAG_LEN);

	/* Transmit the Retry packet. */
	quic_lower_xmit(sk, skb, da, &fl);
	return 0;
}

/* rfc9000#section-17.2.1:
 *
 * Version Negotiation Packet {
 *   Header Form (1) = 1,
 *   Unused (7),
 *   Version (32) = 0,
 *   Destination Connection ID Length (8),
 *   Destination Connection ID (0..2040),
 *   Source Connection ID Length (8),
 *   Source Connection ID (0..2040),
 *   Supported Version (32) ...,
 * }
 *
 * A Version Negotiation packet is inherently not version specific. Upon
 * receipt by a client, it will be identified as a Version Negotiation packet
 * based on the Version field having a value of 0.
 *
 * The Version Negotiation packet is a response to a client packet that
 * contains a version that is not supported by the server. It is only sent by
 * servers.
 */
static int quic_packet_version_create_and_xmit(struct sock *sk, gfp_t gfp)
{
	struct quic_packet *packet = quic_packet(sk);
	union quic_addr *da = &packet->saddr;
	struct quichshdr *hdr;
	struct sk_buff *skb;
	u32 len, hlen, i;
	struct flowi fl;
	int err;
	u8 *p;

	/* Clear routing cache and compute flow route. */
	__sk_dst_reset(sk);
	err = quic_flow_route(sk, da, &packet->daddr, &fl);
	if (err < 0)
		return err;

	/* Compute packet length: header + supported version list. */
	len = QUIC_LONG_HLEN(&packet->dcid, &packet->scid) +
	      QUIC_VERSION_LEN * QUIC_VERSION_NUM;
	hlen = quic_encap_len(da) + MAX_HEADER;
	skb = alloc_skb(hlen + len, gfp);
	if (!skb)
		return -ENOMEM;
	skb_reserve(skb, (int)(hlen + len));

	/* Build Long Packet header. */
	hdr = skb_push(skb, len);
	hdr->form = QUIC_PACKET_FORM_LONG;
	hdr->fixed = 1;
	hdr->type = 0;
	hdr->reserved = 0;
	hdr->pnl = 0;

	/* Write zero version. */
	p = (u8 *)hdr + QUIC_HLEN;
	p = quic_put_int(p, 0, QUIC_VERSION_LEN);
	/* Write Destination Connection ID. */
	p = quic_put_int(p, packet->scid.len, 1);
	p = quic_put_data(p, packet->scid.data, packet->scid.len);
	/* Write Source Connection ID. */
	p = quic_put_int(p, packet->dcid.len, 1);
	p = quic_put_data(p, packet->dcid.data, packet->dcid.len);

	/* Write Supported Versions. */
	for (i = 0; i < QUIC_VERSION_NUM; i++)
		p = quic_put_int(p, quic_versions[i][0], QUIC_VERSION_LEN);

	/* Transmit the Version Negotiation packet. */
	quic_lower_xmit(sk, skb, da, &fl);
	return 0;
}

#define QUIC_STATELESS_RESET_DEF_LEN	64
#define QUIC_STATELESS_RESET_MIN_LEN	(QUIC_HLEN + 5 + QUIC_CONN_ID_TOKEN_LEN)

/* rfc9000#section-10.3:
 *
 * Stateless Reset {
 *   Fixed Bits (2) = 1,
 *   Unpredictable Bits (38..),
 *   Stateless Reset Token (128),
 * }
 *
 * A stateless reset is provided as an option of last resort for an endpoint
 * that does not have access to the state of a connection. A crash or outage
 * might result in peers continuing to send data to an endpoint that is unable
 * to properly continue the connection. An endpoint MAY send a Stateless Reset
 * in response to receiving a packet that it cannot associate with an active
 * connection.
 */
static int quic_packet_stateless_reset_create_and_xmit(struct sock *sk, u32 len,
						       gfp_t gfp)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
	struct quic_packet *packet = quic_packet(sk);
	u32 hlen, tlen = QUIC_CONN_ID_TOKEN_LEN;
	union quic_addr *da = &packet->saddr;
	u8 *p, token[QUIC_CONN_ID_TOKEN_LEN];
	struct sk_buff *skb;
	struct flowi fl;
	int err;

	/* rfc9000#section-10.3.3:
	 *
	 * An endpoint MUST ensure that every Stateless Reset that it sends is
	 * smaller than the packet that triggered it, unless it maintains state
	 * sufficient to prevent looping. In the event of a loop, this results
	 * in packets eventually being too small to trigger a response.
	 */
	if (len <= QUIC_STATELESS_RESET_MIN_LEN)
		return -EINVAL;
	len = min_t(u32, QUIC_STATELESS_RESET_DEF_LEN, len - 1);

	/* Clear routing cache and compute flow route. */
	__sk_dst_reset(sk);
	err = quic_flow_route(sk, da, &packet->daddr, &fl);
	if (err < 0)
		return err;

	/* Generate stateless reset token from DCID in the packet received. */
	err = quic_crypto_derive_secret(crypto, packet->dcid.data,
					packet->dcid.len, "stateless_reset",
					token, tlen);
	if (err)
		return err;

	hlen = quic_encap_len(da) + MAX_HEADER;
	skb = alloc_skb(hlen + len, gfp);
	if (!skb)
		return -ENOMEM;
	skb_reserve(skb, (int)(hlen + len));

	p = skb_push(skb, len);
	/* Write Unpredictable Bits. */
	get_random_bytes(p, len);

	/* Build Short Packet header. */
	quic_hdr(skb)->form = QUIC_PACKET_FORM_SHORT;
	quic_hdr(skb)->fixed = 1;

	/* Write end of packet with stateless reset token. */
	p += (len - QUIC_CONN_ID_TOKEN_LEN);
	quic_put_data(p, token, QUIC_CONN_ID_TOKEN_LEN);

	/* Transmit the Stateless Reset packet. */
	quic_lower_xmit(sk, skb, da, &fl);
	return 0;
}

/* Generate and send a CONNECTION_CLOSE frame on a listening socket in response
 * to invalid client Initial packets. No accept socket exists yet to handle it.
 */
static int quic_packet_refuse_close_create_and_xmit(struct sock *sk,
						    u32 errcode)
{
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_packet *packet = quic_packet(sk);
	u8 level = QUIC_CRYPTO_INITIAL;
	struct quic_conn_id *active;
	int err;

	/* Set our DCID = client's SCID, and our SCID = client's DCID. */
	active = quic_conn_id_active(quic_dest(sk));
	quic_conn_id_update(active, packet->scid.data, packet->scid.len);
	active = quic_conn_id_active(quic_source(sk));
	quic_conn_id_update(active, packet->dcid.data, packet->dcid.len);
	/* Use path[1] for sending; path[0] remains for listening only. */
	quic_path_set_saddr(paths, 1, &packet->daddr);
	quic_path_set_daddr(paths, 1, &packet->saddr);

	/* Reinstall Initial keys for encryption with the client's version. */
	err = quic_packet_version_change(sk, active, packet->version);
	if (err)
		return err;
	/* Set errcode used in CLOSE frame and Transmit it at Initial level. */
	quic_outq(sk)->close_errcode = errcode;
	quic_outq_transmit_frame(sk, QUIC_FRAME_CONNECTION_CLOSE, &level, 1,
				 false, GFP_KERNEL);
	return 0;
}

/* Process an incoming packet on a listening QUIC socket.
 *
 * Depending on the packet type and state, this may involve creating a request
 * socket for a new connection, responding with a Stateless Reset for
 * unexpected non-Initial packets (Handshake, 0-RTT, 1-RTT, Retry, or invalid
 * packets), issuing a Retry packet for address validation when needed, or
 * sending a Version Negotiation packet if the client's QUIC version is
 * unsupported. 0-RTT packets may be silently dropped in multi-ALPN setups.
 */
static int quic_packet_listen_process(struct sock *sk, struct sk_buff *skb,
				      gfp_t gfp)
{
	struct quic_packet *packet = quic_packet(sk);
	u32 version, errcode, toff, len = skb->len;
	struct quic_skb_cb *cb = QUIC_SKB_CB(skb);
	u8 *p = skb->data, type, retry = 0;
	struct net *net = sock_net(sk);
	struct quic_conn_id odcid = {};
	struct quic_request_sock *req;
	struct quic_data alpns = {};
	struct quic_crypto *crypto;
	struct quic_data token;
	u64 length;
	int err;

	/* Read Destination address and Source address from the packet. */
	quic_get_msg_addrs(skb, &packet->daddr, &packet->saddr);

	if (quic_hshdr(skb)->form == QUIC_PACKET_FORM_SHORT) {
		/* rfc9000#section-10.3:
		 *
		 * An endpoint MAY send a Stateless Reset in response to
		 * receiving a packet that it cannot associate with an active
		 * connection.
		 */
		if (len < QUIC_HLEN + QUIC_CONN_ID_DEF_LEN) {
			QUIC_INC_STATS(net, QUIC_MIB_PKT_INVHDRDROP);
			kfree_skb(skb);
			return -EINVAL;
		}
		/* We currently only issue Connection ID with size
		 * QUIC_CONN_ID_DEF_LEN.
		 */
		quic_conn_id_update(&packet->dcid,
				    (u8 *)quic_hdr(skb) + QUIC_HLEN,
				    QUIC_CONN_ID_DEF_LEN);
		/* Send a Stateless Reset for this 1-RTT packet. */
		err = quic_packet_stateless_reset_create_and_xmit(sk, len, gfp);
		consume_skb(skb);
		return err;
	}

	/* Read VERSION, Destination Connection ID and Source Connection ID. */
	err = quic_packet_get_long_header(&packet->dcid, &packet->scid,
					  &version, &p, &len);
	if (err) {
		QUIC_INC_STATS(net, QUIC_MIB_PKT_INVHDRDROP);
		kfree_skb(skb);
		return err;
	}

	req = quic_request_sock_lookup(sk);
	if (req) /* If request sock already exists, enqueue packet directly. */
		return quic_request_sock_backlog_tail(sk, req, skb);

	if (quic_accept_sock_exists(sk, skb))
		return 0; /* Already handled by matched accept socket. */

	/* rfc9000#section-6.1:
	 *
	 * An endpoint MUST NOT send a Version Negotiation packet in response
	 * to receiving a Version Negotiation packet.
	 */
	if (!version) {
		QUIC_INC_STATS(net, QUIC_MIB_PKT_INVHDRDROP);
		kfree_skb(skb);
		return -EINVAL;
	}
	if (!quic_packet_compatible_versions(version)) {
		/* rfc9000#section-5.2.2:
		 *
		 * If a server receives a packet that indicates an unsupported
		 * version and if the packet is large enough to initiate a new
		 * connection for any supported version, the server SHOULD send
		 * a Version Negotiation packet as described in Section 6.1.
		 */
		if (ntohs(udp_hdr(skb)->len) <
		    sizeof(struct udphdr) + QUIC_MIN_UDP_PAYLOAD) {
			kfree_skb(skb);
			return -EINVAL;
		}
		/* rfc9000#section-6.1:
		 *
		 * If the version selected by the client is not acceptable to
		 * the server, the server responds with a Version Negotiation
		 * packet. This includes a list of versions that the server
		 * will accept.
		 */
		err = quic_packet_version_create_and_xmit(sk, gfp);
		consume_skb(skb);
		return err;
	}

	/* Read Packet Type. */
	type = quic_packet_version_get_type(version, quic_hshdr(skb)->type);
	if (type != QUIC_PACKET_INITIAL) { /* Send a Stateless Reset. */
		/* Silently drop 0-RTT packets when routed to wrong listener.
		 * In multi-ALPN setups, 0-RTT packets arriving before accept()
		 * may fall back to listener lookup with empty ALPN, matching
		 * any listener instead of the correct one. Sending Stateless
		 * Reset would incorrectly terminate the connection.
		 */
		if (type == QUIC_PACKET_0RTT &&
		    static_branch_unlikely(&quic_alpn_demux_key)) {
			kfree_skb(skb);
			return -EINVAL;
		}
		err = quic_packet_stateless_reset_create_and_xmit(sk, skb->len,
								  gfp);
		consume_skb(skb);
		return err;
	}

	/* This Destination Connection ID MUST be at least 8 bytes in length. */
	if (packet->dcid.len < QUIC_CONN_ID_DEF_LEN) {
		QUIC_INC_STATS(net, QUIC_MIB_PKT_INVHDRDROP);
		kfree_skb(skb);
		return -EINVAL;
	}

	if (ntohs(udp_hdr(skb)->len) <
	    sizeof(struct udphdr) + QUIC_MIN_UDP_PAYLOAD) {
		kfree_skb(skb);
		return -EINVAL;
	}

	err = quic_packet_get_token(&token, &p, &len); /* Read Token. */
	if (err) {
		QUIC_INC_STATS(net, QUIC_MIB_PKT_INVHDRDROP);
		kfree_skb(skb);
		return err;
	}
	if (token.len)
		toff = token.data - skb->data;

	/* Associate skb with sk to ensure sk is valid if skb is delayed to
	 * process in workqueue.
	 */
	WARN_ON_ONCE(!skb_set_owner_sk_safe(skb, sk));
	packet->version = version;
	if (!cb->resume && static_branch_unlikely(&quic_alpn_demux_key)) {
		if (quic_packet_deferred_schedule(skb))
			return -EINPROGRESS;
		if (!quic_get_var(&p, &len, &length) || length > (u64)len) {
			QUIC_INC_STATS(net, QUIC_MIB_PKT_INVHDRDROP);
			kfree_skb(skb);
			return -EINVAL;
		}
		cb->length = (u16)length;
		cb->number_offset = (u16)(p - skb->data);
		err = quic_packet_get_alpn(skb, &alpns);
		if (err) {
			kfree_skb(skb);
			return err;
		}
		if (quic_listen_sock_switch(skb, &alpns))
			return 0; /* Switched to different listen socket. */
		if (token.len) /* Update after skb->data may change. */
			token.data = skb->data + toff;
	}

	/* Save original DCID for future token validation or Retry logic. */
	quic_conn_id_update(&odcid, packet->dcid.data, packet->dcid.len);
	/* If configured to validate client addresses, handle token logic. */
	if (quic_outq(sk)->validate_peer_address) {
		if (quic_packet_deferred_schedule(skb))
			return 0;
		if (!token.len) {
			/* rfc9000#section-8.1.2:
			 *
			 * Upon receiving the client's Initial packet, the
			 * server can request address validation by sending a
			 * Retry packet containing a token.
			 */
			err = quic_packet_retry_create_and_xmit(sk);
			consume_skb(skb);
			return err;
		}

		/* Distinguish token source: Retry packet or NEW_TOKEN frame. */
		retry = *(u8 *)token.data == QUIC_TOKEN_FLAG_RETRY;

		/* Verify Token. */
		crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
		err = quic_crypto_verify_token(crypto, &packet->saddr,
					       sizeof(packet->saddr),
					       &odcid, token.data, token.len);
		if (err) {
			if (!retry) {
				err = quic_packet_retry_create_and_xmit(sk);
				consume_skb(skb);
				return err;
			}
			/* rfc9000#section-8.1.3:
			 *
			 * If a server receives a client Initial that contains
			 * an invalid Retry token but is otherwise valid, it
			 * knows the client will not accept another Retry
			 * token.  The server SHOULD immediately close the
			 * connection with an INVALID_TOKEN error.
			 */
			errcode = QUIC_TRANSPORT_ERROR_INVALID_TOKEN;
			quic_packet_refuse_close_create_and_xmit(sk, errcode);
			consume_skb(skb);
			return err;
		}
	}

	/* Add request sock for this new QUIC connection. */
	req = quic_request_sock_create(sk, &odcid, retry, gfp);
	if (IS_ERR(req)) {
		if (quic_packet_deferred_schedule(skb))
			return 0;
		/* rfc9000#section-5.2.2:
		 *
		 * If a server refuses to accept a new connection, it SHOULD
		 * send an Initial packet containing a CONNECTION_CLOSE frame
		 * with error code CONNECTION_REFUSED.
		 */
		errcode = QUIC_TRANSPORT_ERROR_CONNECTION_REFUSED;
		quic_packet_refuse_close_create_and_xmit(sk, errcode);
		consume_skb(skb);
		return PTR_ERR(req);
	}
	/* Queue the Initial packet, then publish to accept queue. */
	err = quic_request_sock_backlog_tail(sk, req, skb);
	if (err) {
		kfree(req);
		return err;
	}
	quic_request_sock_enqueue(sk, req);
	return 0;
}

static int quic_packet_handshake_process(struct sock *sk, struct sk_buff *skb,
					 gfp_t gfp)
{
	kfree_skb(skb);
	return -EOPNOTSUPP;
}

static int quic_packet_app_process(struct sock *sk, struct sk_buff *skb,
				   gfp_t gfp)
{
	kfree_skb(skb);
	return -EOPNOTSUPP;
}

int quic_packet_process(struct sock *sk, struct sk_buff *skb, gfp_t gfp)
{
	if (quic_is_closed(sk)) {
		kfree_skb(skb);
		return 0;
	}

	if (quic_is_listen(sk))
		return quic_packet_listen_process(sk, skb, gfp);

	if (quic_hdr(skb)->form == QUIC_PACKET_FORM_LONG)
		return quic_packet_handshake_process(sk, skb, gfp);

	return quic_packet_app_process(sk, skb, gfp);
}

/* Work function to process packets in the deferred list. */
static void quic_packet_deferred_work(struct work_struct *work)
{
	struct quic_sock *qs = container_of(work, struct quic_sock, work);
	struct sock *sk = &qs->inet.sk;
	struct sk_buff_head *head;
	struct sk_buff *skb;

	lock_sock(sk);
	head = &quic_packet(sk)->deferred_list;
	while ((skb = __skb_dequeue(head)) != NULL)
		quic_packet_process(sk, skb, GFP_KERNEL);
	release_sock(sk);
	sock_put(sk);
}

/* Make these fixed for easy coding. */
#define QUIC_PACKET_NUMBER_LEN	QUIC_PN_MAX_LEN
#define QUIC_PACKET_LENGTH_LEN	4

#define QUIC_MAX_ECN_PROBES	3

static void quic_packet_pack_frames(struct sock *sk, struct sk_buff *skb,
				    struct quic_packet_sent *sent, u16 off)
{
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_packet *packet = quic_packet(sk);
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_skb_cb *cb = QUIC_SKB_CB(skb);
	struct quic_frame *frame, *next;
	u64 now = quic_ktime_get_us();
	struct quic_frame_frag *frag;
	struct quic_pnspace *space;
	u8 *p = skb->data + off;
	s64 number;

	space = quic_pnspace(sk, packet->level);
	number = space->next_pn++;

	/* Store packet metadata in skb CB for later use (e.g., encryption). */
	cb->number_len = QUIC_PACKET_NUMBER_LEN;
	cb->number_offset = off;
	cb->number = number;
	cb->level = packet->level;
	cb->path = packet->path;

	p = quic_put_int(p, number, cb->number_len); /* Write packet number. */

	list_for_each_entry_safe(frame, next, &packet->frame_list, list) {
		list_del(&frame->list);
		/* Write main frame data and appended fragments. */
		p = quic_put_data(p, frame->data, frame->dlen);
		for (frag = frame->flist; frag; frag = frag->next)
			p = quic_put_data(p, frag->data, frag->dlen);
		pr_debug("%s: num=%llu type=%u len=%u frame_len=%u level=%u\n",
			 __func__, number, frame->type, skb->len, frame->len,
			 packet->level);
		if (!quic_frame_ack_eliciting(frame->type)) {
			/* CONNECTION_CLOSE must be encrypted synchronously. */
			if (quic_frame_close(frame->type))
				cb->sync = 1;
			/* Skip non-ACK-eliciting frames for tracking. */
			quic_frame_put(frame);
			continue;
		}
		if (frame->number < 0) {
			/* First time sending: record packet number and adjust
			 * unsent byte count.
			 */
			frame->number = number;
			outq->unsent_bytes -= frame->bytes;
		}
		/* Move frame to transmitted queue. */
		quic_outq_transmitted_tail(sk, frame);
		/* Hold frame in sent packet record. */
		sent->frame_array[sent->frames++] = quic_frame_get(frame);
	}

	if (packet->padding) /* Pack the padding frame if any. */
		memset(p, 0, packet->padding);

	/* Track bytes sent before address validation to respect amplification
	 * limits for server.
	 */
	if (quic_is_serv(sk) && !paths->validated)
		paths->ampl_sndlen += packet->len;

	if (!sent) /* Packet doesn't need ACK/loss tracking. */
		return;

	/* Update the last sent timestamp if this packet is ACK-eliciting.
	 * This is important for loss detection and PTO (Probe Timeout) logic.
	 */
	space->last_sent_time = now;

	/* rfc9000#section-13.4.2:
	 *
	 * To perform ECN validation for a new path:
	 *
	 * The endpoint sets an ECT(0) codepoint in the IP header of early
	 * outgoing packets sent on a new path to the peer.
	 */
	if (packet->level == QUIC_CRYPTO_APP &&
	    paths->ecn_probes < QUIC_MAX_ECN_PROBES &&
	    quic_path_alt_state(paths, QUIC_PATH_ALT_NONE)) {
		paths->ecn_probes++;
		cb->ecn = INET_ECN_ECT_0;
		sent->ecn = INET_ECN_ECT_0;
	}
	/* Fill metadata for this sent packet.  Convert CRYPTO level to PN
	 * space level since 0-RTT and 1-RTT share PN space.
	 */
	sent->number = number;
	sent->sent_time = now;
	sent->len = packet->len;
	sent->level = (packet->level % QUIC_CRYPTO_EARLY);

	space->inflight += sent->len;
	outq->inflight += sent->len;
	/* Append packet to sent list for loss and ACK tracking. */
	quic_outq_packet_sent_tail(sk, sent);

	/* Call cong.on_packet_sent() where it does pacing time update. */
	quic_cong_on_packet_sent(quic_cong(sk), sent->sent_time, sent->len,
				 number);
	/* Refresh loss detection timer after sending data. */
	quic_outq_update_loss_timer(sk);
}

static struct quic_packet_sent *quic_packet_sent_alloc(u16 frames, gfp_t gfp)
{
	u32 len = frames * sizeof(struct quic_frame *);
	struct quic_packet_sent *sent;

	sent = kmalloc(sizeof(*sent) + len, gfp | __GFP_ACCOUNT);
	if (sent) {
		sent->frames = 0;
		sent->gap = 0;
		sent->ecn = 0;
	}

	return sent;
}

/* rfc9000#section-17.2.2:
 *
 * Initial Packet {
 *   Header Form (1) = 1,
 *   Fixed Bit (1) = 1,
 *   Long Packet Type (2) = 0,
 *   Reserved Bits (2),
 *   Packet Number Length (2),
 *   Version (32),
 *   Destination Connection ID Length (8),
 *   Destination Connection ID (0..160),
 *   Source Connection ID Length (8),
 *   Source Connection ID (0..160),
 *   Token Length (i),
 *   Token (..),
 *   Length (i),
 *   Packet Number (8..32),
 *   Packet Payload (8..),
 * }
 *
 * An Initial packet uses long headers with a type value of 0x00. It carries
 * the first CRYPTO frames sent by the client and server to perform key
 * exchange, and it carries ACK frames in either direction.
 *
 * rfc9000#section-17.2.4:
 *
 * Handshake Packet {
 *   Header Form (1) = 1,
 *   Fixed Bit (1) = 1,
 *   Long Packet Type (2) = 2,
 *   Reserved Bits (2),
 *   Packet Number Length (2),
 *   Version (32),
 *   Destination Connection ID Length (8),
 *   Destination Connection ID (0..160),
 *   Source Connection ID Length (8),
 *   Source Connection ID (0..160),
 *   Length (i),
 *   Packet Number (8..32),
 *   Packet Payload (8..),
 * }
 *
 * A Handshake packet uses long headers with a type value of 0x02, followed by
 * the Length and Packet Number fields. The first byte contains the Reserved
 * and Packet Number Length bits. It is used to carry cryptographic handshake
 * messages and acknowledgments from the server and client.
 *
 * rfc9000#section-17.2.3:
 *
 * 0-RTT Packet {
 *   Header Form (1) = 1,
 *   Fixed Bit (1) = 1,
 *   Long Packet Type (2) = 1,
 *   Reserved Bits (2),
 *   Packet Number Length (2),
 *   Version (32),
 *   Destination Connection ID Length (8),
 *   Destination Connection ID (0..160),
 *   Source Connection ID Length (8),
 *   Source Connection ID (0..160),
 *   Length (i),
 *   Packet Number (8..32),
 *   Packet Payload (8..),
 * }
 *
 * A 0-RTT packet uses long headers with a type value of 0x01, followed by the
 * Length and Packet Number fields. The first byte contains the Reserved and
 * Packet Number Length bits. A 0-RTT packet is used to carry "early" data from
 * the client to the server as part of the first flight, prior to handshake
 * completion.
 */
static struct sk_buff *quic_packet_handshake_create(struct sock *sk, gfp_t gfp)
{
	struct quic_conn_id_set *source = quic_source(sk);
	struct quic_conn_id_set *dest = quic_dest(sk);
	struct quic_packet *packet = quic_packet(sk);
	u8 type, fixed = 1, level = packet->level;
	struct quic_packet_sent *sent = NULL;
	struct quic_conn_id *active;
	struct quichshdr *hdr;
	struct sk_buff *skb;
	u32 len, hlen;
	u16 off;
	u8 *p;

	/* Determine packet type based on encryption level. */
	type = QUIC_PACKET_INITIAL;
	if (level == QUIC_CRYPTO_HANDSHAKE) {
		type = QUIC_PACKET_HANDSHAKE;
		fixed = !quic_outq(sk)->grease_quic_bit;
	} else if (level == QUIC_CRYPTO_EARLY) {
		type = QUIC_PACKET_0RTT;
	}

	if (packet->frames || !quic_is_serv(sk)) {
		/* rfc9000#section-14.1:
		 *
		 * A client MUST expand the payload of all UDP datagrams
		 * carrying Initial packets to at least the smallest allowed
		 * maximum datagram size of 1200 bytes by adding PADDING frames
		 * to the Initial packet or by coalescing the Initial packet.
		 * Similarly, a server MUST expand the payload of all UDP
		 * datagrams carrying ack-eliciting Initial packets to at least
		 * the smallest allowed maximum datagram size of 1200 bytes.
		 */
		if (level == QUIC_CRYPTO_INITIAL) {
			len = QUIC_MIN_UDP_PAYLOAD;
			if (packet->len < len) {
				packet->padding += (len - packet->len);
				packet->len = len;
			}
		}
	}
	len = packet->len - quic_packet_taglen(packet);
	if (packet->frames) {
		/* If there are ack-eliciting frames, create packet_sent for
		 * acknowledge and loss detection.
		 */
		sent = quic_packet_sent_alloc(packet->frames, gfp);
		if (!sent) { /* Move pending frames back to the outqueue. */
			pr_debug("%s: failed, frames: %d\n", __func__,
				 packet->frames);
			quic_outq_retransmit_list(sk, &packet->frame_list);
			return NULL;
		}
	}

	/* Allocate skb with space for header + payload + AEAD taglen of Long
	 * Packet.
	 */
	hlen = packet->hlen + MAX_HEADER;
	skb = alloc_skb(hlen + packet->len, gfp);
	if (!skb) {
		kfree(sent);
		quic_outq_retransmit_list(sk, &packet->frame_list);
		return NULL;
	}
	skb->ignore_df = packet->ipfragok;
	skb_reserve(skb, (int)(hlen + len));

	/* Build Long Packet header. */
	hdr = skb_push(skb, len);
	hdr->form = QUIC_PACKET_FORM_LONG;
	hdr->fixed = fixed;
	hdr->type = quic_packet_version_put_type(packet->version, type);
	hdr->reserved = 0;
	hdr->pnl = QUIC_PACKET_NUMBER_LEN - 1;

	/* Write the QUIC version. */
	p = (u8 *)hdr + QUIC_HLEN;
	p = quic_put_int(p, packet->version, QUIC_VERSION_LEN);

	/* Write Destination Connection ID. */
	active = quic_conn_id_active(dest);
	p = quic_put_int(p, active->len, 1);
	p = quic_put_data(p, active->data, active->len);

	/* Write Source Connection ID. */
	active = quic_conn_id_active(source);
	p = quic_put_int(p, active->len, 1);
	p = quic_put_data(p, active->data, active->len);

	/* Write Token if needed. */
	if (level == QUIC_CRYPTO_INITIAL) { /* Only Initial carries tokens. */
		hlen = quic_token(sk)->len;
		p = quic_put_var(p, hlen);
		p = quic_put_data(p, quic_token(sk)->data, hlen);
	}

	/* Write Length. */
	off = (u16)(p + QUIC_PACKET_LENGTH_LEN - skb->data);
	p = quic_put_varint(p, packet->len - off, QUIC_PACKET_LENGTH_LEN);

	/* Pack Packet Number and actual frames starting at offset 'off'. */
	quic_packet_pack_frames(sk, skb, sent, off);
	return skb;
}

/* Ensures the packet number is within the valid range. */
static int quic_packet_number_check(struct sock *sk, gfp_t gfp)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_pnspace *space;

	/* Check if the next packet number is within the allowed range. */
	space = quic_pnspace(sk, packet->level);
	if (space->next_pn + 1 <= QUIC_PN_MAX)
		return 0;

	/* Move pending frames back to the outqueue. */
	quic_outq_retransmit_list(sk, &packet->frame_list);

	/* rfc9000#section-12.3:
	 *
	 * If the packet number for sending reaches 2^62-1, the sender MUST
	 * close the connection without sending a CONNECTION_CLOSE frame or any
	 * further packets.
	 */
	if (!quic_is_closed(sk)) {
		struct quic_connection_close c = {};

		/* Notify application that the connection is being closed. */
		quic_inq_event_recv(sk, QUIC_EVENT_CONNECTION_CLOSE, &c,
				    sizeof(c), gfp);
		quic_set_state(sk, QUIC_SS_CLOSED);
	}
	return -EPIPE;
}

/* rfc9000#section-17.3.1:
 *
 * 1-RTT Packet {
 *   Header Form (1) = 0,
 *   Fixed Bit (1) = 1,
 *   Spin Bit (1),
 *   Reserved Bits (2),
 *   Key Phase (1),
 *   Packet Number Length (2),
 *   Destination Connection ID (0..160),
 *   Packet Number (8..32),
 *   Packet Payload (8..),
 * }
 *
 * A 1-RTT packet uses a short packet header. It is used after the version and
 * 1-RTT keys are negotiated.
 */
static struct sk_buff *quic_packet_app_create(struct sock *sk, gfp_t gfp)
{
	struct quic_conn_id_set *id_set = quic_dest(sk);
	struct quic_packet *packet = quic_packet(sk);
	struct quic_packet_sent *sent = NULL;
	struct quic_conn_id *active;
	struct sk_buff *skb;
	struct quichdr *hdr;
	u32 len, hlen;
	u16 off;

	if (packet->frames) {
		if (packet->path_validating) {
			/* rfc9000#section-8.2:
			 *
			 * An endpoint MUST expand datagrams that contain a
			 * PATH_CHALLENGE/PATH_RESPONSE frame to at least the
			 * smallest allowed maximum datagram size of 1200
			 * bytes.
			 */
			len = QUIC_MIN_UDP_PAYLOAD;
			if (packet->len < len) {
				packet->padding += (len - packet->len);
				packet->len = len;
			}
		}
		/* If there are ack-eliciting frames, create packet_sent for
		 * acknowledge and loss detection.
		 */
		sent = quic_packet_sent_alloc(packet->frames, gfp);
		if (!sent) { /* Move pending frames back to the outqueue. */
			pr_debug("%s: failed, frames: %d\n", __func__,
				 packet->frames);
			quic_outq_retransmit_list(sk, &packet->frame_list);
			return NULL;
		}
	}

	/* Allocate skb with space for header + payload + AEAD taglen of Short
	 * Packet.
	 */
	len = packet->len - quic_packet_taglen(packet);
	hlen = packet->hlen + MAX_HEADER;
	skb = alloc_skb(hlen + packet->len, gfp);
	if (!skb) { /* Move pending frames back to the outqueue. */
		kfree(sent);
		quic_outq_retransmit_list(sk, &packet->frame_list);
		return NULL;
	}
	skb->ignore_df = packet->ipfragok;
	skb_reserve(skb, (int)(hlen + len));

	/* Build Short Packet header. */
	hdr = skb_push(skb, len);
	hdr->form = QUIC_PACKET_FORM_SHORT;
	hdr->fixed = !quic_outq(sk)->grease_quic_bit;
	hdr->spin = 0;
	hdr->reserved = 0;
	hdr->key = 0;
	hdr->pnl = QUIC_PACKET_NUMBER_LEN - 1;

	/* Choose the active destination connection ID based on path. */
	active = quic_conn_id_choose(id_set, packet->path);
	quic_put_data((u8 *)hdr + QUIC_HLEN, active->data, active->len);
	off = (u16)(active->len + sizeof(struct quichdr));

	/* Pack Packet Number and actual frames starting at offset 'off'. */
	quic_packet_pack_frames(sk, skb, sent, off);
	return skb;
}

/* Update the MSS and inform congestion control. */
void quic_packet_mss_update(struct sock *sk, u32 mss)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_cong *cong = quic_cong(sk);

	/* Limit MSS for regular QUIC packets to the max UDP payload size. */
	if (outq->max_udp_payload_size && mss > outq->max_udp_payload_size)
		mss = outq->max_udp_payload_size;
	packet->mss = (u16)mss;

	/* Update congestion control with new payload space (including tag). */
	quic_cong_set_mss(cong, packet->mss);
	quic_outq_sync_window(sk, cong->window);
}

/* Perform routing for the QUIC packet on the specified path, update header
 * length and MSS accordingly, reset path and start PMTU timer.
 */
int quic_packet_route(struct sock *sk)
{
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_packet *packet = quic_packet(sk);
	union quic_addr *sa, *da;
	u32 pmtu;
	int err;

	da = quic_path_daddr(paths, packet->path);
	sa = quic_path_saddr(paths, packet->path);
	err = quic_flow_route(sk, da, sa, &paths->fl);
	if (err)
		return err < 0 ? err : 0;

	packet->hlen = quic_encap_len(da);
	pmtu = clamp(dst_mtu(__sk_dst_get(sk)),
		     QUIC_PATH_MIN_PMTU, QUIC_PATH_MAX_PMTU);
	quic_packet_mss_update(sk, pmtu - packet->hlen);

	quic_path_pl_reset(paths);
	quic_timer_reset(sk, QUIC_TIMER_PMTU, paths->plpmtud_interval);
	return 0;
}

/* Return QUIC packet header overhead for the given level and path. Includes
 * packet number, connection IDs, and for long headers also version, length,
 * and Initial token (if present). Excludes payload.
 */
u16 quic_packet_overhead(struct sock *sk, u8 level, u8 path)
{
	struct quic_conn_id_set *source = quic_source(sk);
	struct quic_conn_id_set *dest = quic_dest(sk);
	u16 len = QUIC_HLEN;

	len += QUIC_PACKET_NUMBER_LEN; /* Packet number length. */
	len += quic_conn_id_choose(dest, path)->len; /* DCID length. */
	if (level == QUIC_CRYPTO_APP)
		return len;

	len += 1; /* Length byte for DCID. */
	/* Length byte + SCID length. */
	len += 1 + quic_conn_id_active(source)->len;
	/* Include token for Initial packets. */
	if (level == QUIC_CRYPTO_INITIAL)
		len += quic_var_len(quic_token(sk)->len) + quic_token(sk)->len;
	len += QUIC_VERSION_LEN; /* Version length. */
	len += QUIC_PACKET_LENGTH_LEN; /* Packet length field. */

	return len;
}

/* Configure the QUIC packet header and routing based on encryption level and
 * path.
 */
int quic_packet_config(struct sock *sk, u8 level, u8 path)
{
	struct quic_packet *packet = quic_packet(sk);

	/* If packet already has data, no need to reconfigure. */
	if (!quic_packet_empty(packet))
		return 0;

	packet->path_validating = 0;
	packet->ipfragok = 0;
	packet->padding = 0;
	packet->frames = 0;
	packet->last = 0;

	packet->level = level;
	packet->overhead = quic_packet_overhead(sk, level, path);
	packet->len = packet->overhead + quic_packet_taglen(packet);

	/* Allow fragmentation for handshake packets if PLPMTUD is enabled, as
	 * MTU discovery does not rely on ICMP Packet Too Big once PLPMTUD is
	 * enabled.
	 */
	packet->ipfragok = level && !!quic_paths(sk)->plpmtud_interval;

	if (packet->path != path) {
		/* Path changed; update and reset routing cache */
		packet->path = path;
		__sk_dst_reset(sk);
	}

	/* Perform routing and MSS update for the configured packet. */
	return quic_packet_route(sk);
}

static int quic_packet_xmit(struct sock *sk, struct sk_buff *skb, gfp_t gfp);

void quic_packet_flush_txq(struct sock *sk)
{
	struct sk_buff_head *head;
	struct quic_skb_cb *cb;
	struct sk_buff *skb;

	head = &sk->sk_write_queue;
	if (quic_is_closed(sk)) { /* Socket closed: drop all pending skbs. */
		__skb_queue_purge(head);
		return;
	}

	while ((skb = __skb_dequeue(head)) != NULL) {
		cb = QUIC_SKB_CB(skb);
		if (quic_packet_config(sk, cb->level, cb->path)) {
			kfree_skb(skb);
			continue;
		}
		cb->resume = 1; /* Mark this skb as encrypted before sending. */
		quic_packet_xmit(sk, skb, GFP_ATOMIC);
	}
	quic_packet_flush(sk);
}

static void quic_packet_encrypt_done(struct sk_buff *skb)
{
	struct sock *sk = skb->sk;

	sock_hold(sk);
	local_bh_disable();
	bh_lock_sock(sk);
	__skb_queue_tail(&sk->sk_write_queue, skb);
	if (sock_owned_by_user(sk)) {
		if (!test_and_set_bit(QUIC_TXQ_DEFERRED, &sk->sk_tsq_flags))
			sock_hold(sk);
		goto out;
	}

	quic_packet_flush_txq(sk);
out:
	bh_unlock_sock(sk);
	local_bh_enable();
	sock_put(sk);
}

/* Coalescing Packets. */
static int quic_packet_bundle(struct sock *sk, struct sk_buff *skb)
{
	struct quic_skb_cb *head_cb, *cb = QUIC_SKB_CB(skb);
	struct quic_packet *packet = quic_packet(sk);
	struct sk_buff *p;

	if (!packet->head) /* First packet to bundle: initialize the head. */
		goto init;

	/* If bundling would exceed MSS, flush the current bundle. */
	if (packet->head->len + skb->len > packet->mss) {
		quic_packet_flush(sk);
		goto init;
	}
	/* Bundle it and update metadata for the aggregate skb. */
	skb_orphan(skb);
	p = packet->head;
	head_cb = QUIC_SKB_CB(p);
	if (head_cb->last == p)
		skb_shinfo(p)->frag_list = skb;
	else
		head_cb->last->next = skb;
	p->data_len += skb->len;
	p->truesize += skb->truesize;
	p->len += skb->len;
	head_cb->last = skb;
	head_cb->ecn |= cb->ecn;  /* Merge ECN flags. */

out:
	/* rfc9000#section-12.2: Packets with a short header (Section 17.3) do
	 * not contain a Length field and so cannot be followed by other
	 * packets in the same UDP datagram.
	 *
	 * so Return 1 to flush if it is a Short header packet.
	 */
	return !cb->level;
init:
	packet->head = skb;
	cb->last = skb;
	goto out;
}

/* Transmit a QUIC packet, possibly encrypting and bundling it. */
static int quic_packet_xmit(struct sock *sk, struct sk_buff *skb, gfp_t gfp)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_skb_cb *cb = QUIC_SKB_CB(skb);
	struct net *net = sock_net(sk);
	int err;

	/* Associate skb with sk to ensure sk is valid during async encryption
	 * completion.
	 */
	WARN_ON_ONCE(!skb_set_owner_sk_safe(skb, sk));

	/* Skip encryption if taglen == 0 (e.g., disable_1rtt_encryption). */
	if (!quic_packet_taglen(packet))
		goto xmit;

	cb->crypto_done = quic_packet_encrypt_done;
	err = quic_crypto_encrypt(quic_crypto(sk, packet->level), skb, gfp);
	if (err) {
		if (err == -EKEYEXPIRED && !quic_is_closed(sk)) {
			struct quic_connection_close c = {};

			quic_inq_event_recv(sk, QUIC_EVENT_CONNECTION_CLOSE, &c,
					    sizeof(c), gfp);
			quic_set_state(sk, QUIC_SS_CLOSED);
		}
		if (err != -EINPROGRESS) {
			QUIC_INC_STATS(net, QUIC_MIB_PKT_ENCDROP);
			kfree_skb(skb);
			return err;
		}
		QUIC_INC_STATS(net, QUIC_MIB_PKT_ENCBACKLOGS);
		return err;
	}
	if (!cb->resume) /* Encryption completes synchronously. */
		QUIC_INC_STATS(net, QUIC_MIB_PKT_ENCFASTPATHS);

xmit:
	if (quic_packet_bundle(sk, skb))
		quic_packet_flush(sk);
	return 0;
}

/* Create and transmit a new QUIC packet. */
int quic_packet_create_and_xmit(struct sock *sk, gfp_t gfp)
{
	struct quic_packet *packet = quic_packet(sk);
	struct sk_buff *skb;
	int err;

	err = quic_packet_number_check(sk, gfp);
	if (err)
		goto err;

	if (packet->level)
		skb = quic_packet_handshake_create(sk, gfp);
	else
		skb = quic_packet_app_create(sk, gfp);
	if (!skb) {
		err = -ENOMEM;
		goto err;
	}

	err = quic_packet_xmit(sk, skb, gfp);
	if (err && err != -EINPROGRESS)
		goto err;

	return 0;
err:
	pr_debug("%s: err: %d\n", __func__, err);
	return err;
}

/* Flush any coalesced/bundled QUIC packets. */
void quic_packet_flush(struct sock *sk)
{
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_packet *packet = quic_packet(sk);

	if (packet->head) {
		quic_lower_xmit(sk, packet->head,
				quic_path_daddr(paths, packet->path),
				&paths->fl);
		packet->head = NULL;
	}
}

/* Append a frame to the tail of the current QUIC packet. */
int quic_packet_tail(struct sock *sk, struct quic_frame *frame)
{
	struct quic_packet *packet = quic_packet(sk);

	/* Reject frame if it doesn't match the packet's encryption level or
	 * path, or if padding is already in place (no further frames should be
	 * added).
	 */
	if (frame->level != (packet->level % QUIC_CRYPTO_EARLY) ||
	    frame->path != packet->path || packet->padding || packet->last)
		return 0;

	/* Check if frame would exceed the current datagram MSS (excluding AEAD
	 * tag).
	 */
	if (packet->len + frame->len + frame->padding > packet->mss) {
		/* If some data has already been added to packet, bail out. */
		if (!quic_packet_empty(packet))
			return 0;
		/* Otherwise, allow IP fragmentation for this packet unless
		 * it’s a PING probe.
		 */
		if (!quic_frame_ping(frame->type))
			packet->ipfragok = 1;
	}
	if (frame->padding) {
		packet->padding = frame->padding;
		packet->len += frame->padding;
	}

	if (quic_frame_ack_eliciting(frame->type)) {
		if (quic_frame_path_validating(frame->type))
			packet->path_validating = 1;
		packet->frames++;
	}

	list_move_tail(&frame->list, &packet->frame_list);
	packet->len += frame->len;
	if (frame->last)
		packet->last = 1;
	return frame->len;
}

void quic_packet_init(struct sock *sk)
{
	struct quic_packet *packet = quic_packet(sk);

	INIT_LIST_HEAD(&packet->frame_list);
	skb_queue_head_init(&packet->deferred_list);
	skb_queue_head_init(&packet->backlog_list);
	INIT_WORK(quic_work(sk), quic_packet_deferred_work);

	packet->mss = QUIC_MIN_UDP_PAYLOAD;
	packet->taglen = QUIC_TAG_LEN;
	packet->version = QUIC_VERSION_V1;
}

void quic_packet_free(struct sock *sk)
{
	struct quic_packet *packet = quic_packet(sk);

	flush_work(quic_work(sk));
	__skb_queue_purge(&packet->deferred_list);
	__skb_queue_purge(&packet->backlog_list);
}
