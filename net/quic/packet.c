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
		if (quic_packet_route(sk))
			return;

		dst = __sk_dst_get(sk);
		if (dst)
			dst->ops->update_pmtu(dst, sk, NULL, info, true);
		quic_packet_mss_update(sk, info - packet->hlen);
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
	 * reversed when parsed. Only address-based socket lookup is possible
	 * in this case.
	 */
	quic_get_msg_addrs(skb, &saddr, &daddr);
	sk = quic_sock_lookup(skb, &daddr, &saddr, sk, NULL);
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

#define QUIC_PACKET_BACKLOG_MAX		4096

/* Queue a packet for later processing when sleeping is allowed. */
static int quic_packet_backlog_schedule(struct net *net, struct sk_buff *skb)
{
	struct quic_skb_cb *cb = QUIC_SKB_CB(skb);
	struct quic_net *qn = quic_net(net);
	struct sk_buff_head *head;

	if (cb->backlog)
		return 0;

	head = &qn->backlog_list;
	spin_lock_bh(&head->lock);
	if (head->qlen >= QUIC_PACKET_BACKLOG_MAX) {
		spin_unlock_bh(&head->lock);
		QUIC_INC_STATS(net, QUIC_MIB_PKT_RCVDROP);
		kfree_skb(skb);
		return -ENOBUFS;
	}
	cb->backlog = 1;
	__skb_queue_tail(head, skb);
	spin_unlock_bh(&head->lock);

	queue_work(quic_wq, &qn->work);
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

/* Extract ALPN data from a TLS ClientHello message.
 *
 * Parses the TLS ClientHello handshake message to find the ALPN (Application
 * Layer Protocol Negotiation) TLS extension. It validates the TLS ClientHello
 * structure, including version, random, session ID, cipher suites, compression
 * methods, and extensions. Once the ALPN extension is found, the ALPN
 * protocols list is extracted and stored in @alpn.
 *
 * Return: 0 on success or no ALPN found, a negative error code on failed
 * parsing.
 */
static int quic_packet_get_alpn(struct quic_data *alpn, u8 *p, u32 len)
{
	int err = -EINVAL, found = 0, exts = 0;
	u64 length, type;

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
		if (len < (u32)length) /* Incomplete TLS extensions. */
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
	pr_debug("%s: alpn_len: %d\n", __func__, alpn->len);
	return 0;
}

/* Parse ALPN from a QUIC Initial packet.
 *
 * This function processes a QUIC Initial packet to extract the ALPN from the
 * TLS ClientHello message inside the QUIC CRYPTO frame. It verifies packet
 * type, version compatibility, decrypts the packet payload, and locates the
 * CRYPTO frame to parse the TLS ClientHello.  Finally, it calls
 * quic_packet_get_alpn() to extract the ALPN extension data.
 *
 * Return: 0 on success or no ALPN found, a negative error code on failed
 * parsing.
 */
static int quic_packet_parse_alpn(struct sk_buff *skb, struct quic_data *alpn)
{
	struct quic_skb_cb *cb = QUIC_SKB_CB(skb);
	struct quic_conn_id dcid = {}, scid = {};
	struct net *net = sock_net(skb->sk);
	u32 len = skb->len, version;
	struct quic_crypto *crypto;
	u8 *p = skb->data, type;
	struct quic_data token;
	u64 offset, length;
	int err;

	if (!static_branch_unlikely(&quic_alpn_demux_key))
		return 0;
	err = quic_packet_get_long_header(&dcid, &scid, &version, &p, &len);
	if (err)
		return err;
	if (!quic_packet_compatible_versions(version))
		return 0;
	/* Only parse Initial packets. */
	type = quic_packet_version_get_type(version, quic_hshdr(skb)->type);
	if (type != QUIC_PACKET_INITIAL)
		return 0;
	err = quic_packet_get_token(&token, &p, &len);
	if (err)
		return err;
	if (!quic_get_var(&p, &len, &length) || length > (u64)len)
		return -EINVAL;
	if (quic_packet_backlog_schedule(net, skb))
		return -EINPROGRESS;
	cb->length = (u16)length;

	/* Install initial keys for packet decryption to crypto. */
	crypto = &quic_net(net)->crypto;
	err = quic_crypto_initial_keys_install(crypto, &dcid, version, 1);
	if (err)
		return err;
	cb->number_offset = (u16)(p - skb->data);
	cb->sync = 1;
	err = quic_crypto_decrypt(crypto, skb, GFP_KERNEL);
	if (err) {
		QUIC_INC_STATS(net, QUIC_MIB_PKT_DECDROP);
		return err;
	}

	QUIC_INC_STATS(net, QUIC_MIB_PKT_DECFASTPATHS);
	cb->resume = 1; /* Mark this packet as already decrypted. */

	/* Find the QUIC CRYPTO frame. */
	p = skb->data + cb->number_offset + cb->number_len;
	len = cb->length - cb->number_len - QUIC_TAG_LEN;
	for (; len && !(*p); p++, len--) /* Skip the padding frame. */
		;
	if (!len-- || *p++ != QUIC_FRAME_CRYPTO)
		return 0;
	if (!quic_get_var(&p, &len, &offset) || offset)
		return 0;
	if (!quic_get_var(&p, &len, &length) || length > (u64)len)
		return 0;

	/* Parse the TLS CLIENT_HELLO message. */
	return quic_packet_get_alpn(alpn, p, length);
}

/* Lookup listening socket for Client Initial packet (in process context). */
static struct sock *quic_packet_get_listen_sock(struct sk_buff *skb)
{
	union quic_addr daddr, saddr;
	struct quic_data alpns = {};
	struct sock *sk;
	int err;

	quic_get_msg_addrs(skb, &daddr, &saddr);

	err = quic_packet_parse_alpn(skb, &alpns);
	if (err)
		return ERR_PTR(err);

	sk = quic_listen_sock_lookup(skb, &daddr, &saddr, &alpns);
	if (!sk)
		return ERR_PTR(-ENOENT);
	return sk;
}

/* Determine the QUIC socket associated with an incoming packet. */
static struct sock *quic_packet_get_sock(struct sk_buff *skb)
{
	struct quic_skb_cb *cb = QUIC_SKB_CB(skb);
	struct quic_conn_id dcid = {}, *conn_id;
	struct net *net = sock_net(skb->sk);
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
			/* Return associated socket. */
			return quic_conn_id_sk(conn_id);
		}

		/* Fallback: listener socket lookup
		 * (May be used to send a stateless reset from a listen socket).
		 */
		quic_get_msg_addrs(skb, &daddr, &saddr);
		sk = quic_listen_sock_lookup(skb, &daddr, &saddr, &alpns);
		if (sk)
			return sk;
		/* Final fallback: address-based connection lookup
		 * (May be used to receive a stateless reset).
		 */
		sk = quic_sock_lookup(skb, &daddr, &saddr, skb->sk, NULL);
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
		return quic_conn_id_sk(conn_id); /* Return associated socket. */
	}

	/* Fallback: address + DCID lookup
	 * (May be used for 0-RTT or a follow-up Client Initial packet).
	 */
	quic_get_msg_addrs(skb, &daddr, &saddr);
	sk = quic_sock_lookup(skb, &daddr, &saddr, skb->sk, &dcid);
	if (sk)
		return sk;
	/* Final fallback: listener socket lookup
	 * (Used for receiving the first Client Initial packet).
	 */
	err = quic_packet_parse_alpn(skb, &alpns);
	if (err)
		return ERR_PTR(err);
	sk = quic_listen_sock_lookup(skb, &daddr, &saddr, &alpns);
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

	/* Save the UDP socket to skb->sk for later QUIC socket lookup. */
	if (skb_linearize(skb) || !skb_set_owner_sk_safe(skb, sk)) {
		err = -EINVAL;
		goto err;
	}

	/* Look up socket from socket or connection IDs hash tables. */
	sk = quic_packet_get_sock(skb);
	if (IS_ERR(sk)) {
		err = PTR_ERR(sk);
		if (err == -EINPROGRESS)
			return 0;
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
	pr_debug("%s: failed, len: %d, err: %d\n", __func__, skb->len, err);
	QUIC_INC_STATS(net, QUIC_MIB_PKT_RCVDROP);
	kfree_skb(skb);
	return err;
}

static int quic_packet_listen_process(struct sock *sk, struct sk_buff *skb,
				      gfp_t gfp)
{
	kfree_skb(skb);
	return -EOPNOTSUPP;
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

/* Work function to process packets in the backlog queue. */
void quic_packet_backlog_work(struct work_struct *work)
{
	struct quic_net *qn = container_of(work, struct quic_net, work);
	struct sk_buff_head *head = &qn->backlog_list;
	struct sk_buff *skb;
	struct sock *sk;

	while ((skb = skb_dequeue(head)) != NULL) {
		sk = quic_packet_get_listen_sock(skb);
		if (IS_ERR(sk)) {
			QUIC_INC_STATS(sock_net(skb->sk), QUIC_MIB_PKT_RCVDROP);
			kfree_skb(skb);
			continue;
		}

		lock_sock(sk);
		quic_packet_process(sk, skb, GFP_KERNEL);
		release_sock(sk);
		sock_put(sk);
		cond_resched();
	}
}

/* Make these fixed for easy coding. */
#define QUIC_PACKET_NUMBER_LEN	QUIC_PN_MAX_LEN
#define QUIC_PACKET_LENGTH_LEN	4

static struct sk_buff *quic_packet_handshake_create(struct sock *sk, gfp_t gfp)
{
	return NULL;
}

static int quic_packet_number_check(struct sock *sk, gfp_t gfp)
{
	return 0;
}

static struct sk_buff *quic_packet_app_create(struct sock *sk, gfp_t gfp)
{
	return NULL;
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
	packet->mss[QUIC_PACKET_MSS_NORMAL] = (u16)mss;

	/* Update congestion control with new payload space (including tag). */
	quic_cong_set_mss(cong, packet->mss[QUIC_PACKET_MSS_NORMAL]);
	quic_outq_sync_window(sk, cong->window);

	/* Limit MSS for DATAGRAM frame packets to max datagram frame size. */
	if (outq->max_datagram_frame_size && mss >
	    outq->max_datagram_frame_size)
		mss = outq->max_datagram_frame_size;
	packet->mss[QUIC_PACKET_MSS_DGRAM] = (u16)mss;
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

	packet->level = level;
	packet->overhead = quic_packet_overhead(sk, level, path);
	packet->len = packet->overhead + quic_packet_taglen(packet);

	/* Allow fragmentation for handshake packets before PLPMTUD probing
	 * starts. MTU discovery does not rely on ICMP Packet Too Big once
	 * PLPMTUD is enabled.
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

static void quic_packet_encrypt_done(struct sk_buff *skb, int err)
{
	struct sock *sk = skb->sk;

	if (err) {
		QUIC_INC_STATS(sock_net(sk), QUIC_MIB_PKT_ENCDROP);
		kfree_skb(skb);
		pr_debug("%s: err: %d\n", __func__, err);
		return;
	}

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
	if (packet->head->len + skb->len >
	    packet->mss[QUIC_PACKET_MSS_NORMAL]) {
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

	/* Skip encryption if taglen == 0 (e.g., disable_1rtt_encryption). */
	if (!packet->taglen[quic_hdr(skb)->form])
		goto xmit;

	cb->crypto_done = quic_packet_encrypt_done;
	/* Associate skb with sk to ensure sk is valid during async encryption
	 * completion.
	 */
	WARN_ON_ONCE(!skb_set_owner_sk_safe(skb, sk));
	err = quic_crypto_encrypt(quic_crypto(sk, packet->level), skb, gfp);
	if (err) {
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
	    frame->path != packet->path || packet->padding)
		return 0;

	/* Check if frame would exceed the current datagram MSS (excluding AEAD
	 * tag).
	 */
	if (packet->len + frame->len + frame->padding >
	    packet->mss[frame->dgram]) {
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
	return frame->len;
}

void quic_packet_init(struct sock *sk)
{
	struct quic_packet *packet = quic_packet(sk);

	INIT_LIST_HEAD(&packet->frame_list);
	packet->taglen[QUIC_PACKET_FORM_SHORT] = QUIC_TAG_LEN;
	packet->taglen[QUIC_PACKET_FORM_LONG] = QUIC_TAG_LEN;
	packet->mss[QUIC_PACKET_MSS_NORMAL] = QUIC_MIN_UDP_PAYLOAD;
	packet->mss[QUIC_PACKET_MSS_DGRAM] = QUIC_MIN_UDP_PAYLOAD;

	packet->version = QUIC_VERSION_V1;
}
