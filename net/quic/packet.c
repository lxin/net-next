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

/* Supported QUIC versions and their compatible versions. Used for Compatible Version
 * Negotiation in rfc9368#section-2.3.
 */
static u32 quic_versions[QUIC_VERSION_NUM][4] = {
	/* Version,	Compatible Versions */
	{ QUIC_VERSION_V1,	QUIC_VERSION_V2,	QUIC_VERSION_V1,	0 },
	{ QUIC_VERSION_V2,	QUIC_VERSION_V2,	QUIC_VERSION_V1,	0 },
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
		return -1;
	}
	return -1;
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
		return -1;
	}
	return -1;
}

/* Parse QUIC version and connection IDs (DCID and SCID) from a Long header packet buffer. */
static int quic_packet_get_version_and_connid(struct quic_conn_id *dcid, struct quic_conn_id *scid,
					      u32 *version, u8 **pp, u32 *plen)
{
	u64 len, v;

	*pp += QUIC_HLEN;
	*plen -= QUIC_HLEN;

	if (!quic_get_int(pp, plen, &v, QUIC_VERSION_LEN))
		return -EINVAL;
	*version = v;

	if (!quic_get_int(pp, plen, &len, 1) ||
	    len > *plen || len > QUIC_CONN_ID_MAX_LEN)
		return -EINVAL;
	quic_conn_id_update(dcid, *pp, len);
	*plen -= len;
	*pp += len;

	if (!quic_get_int(pp, plen, &len, 1) ||
	    len > *plen || len > QUIC_CONN_ID_MAX_LEN)
		return -EINVAL;
	quic_conn_id_update(scid, *pp, len);
	*plen -= len;
	*pp += len;
	return 0;
}

/* Change the QUIC version for the connection.
 *
 * Frees existing initial crypto keys and installs new initial keys compatible with the new
 * version.
 */
static int quic_packet_version_change(struct sock *sk, struct quic_conn_id *dcid, u32 version)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);

	if (quic_crypto_initial_keys_install(crypto, dcid, version, quic_is_serv(sk)))
		return -1;

	quic_packet(sk)->version = version;
	return 0;
}

/* Select the best compatible QUIC version from offered list.
 *
 * Considers the local preferred version, currently chosen version, and versions offered by
 * the peer. Selects the best compatible version based on client/server role and updates the
 * connection version accordingly.
 */
int quic_packet_select_version(struct sock *sk, u32 *versions, u8 count)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_config *c = quic_config(sk);
	u8 i, pref_found = 0, ch_found = 0;
	u32 preferred, chosen, best = 0;

	preferred = c->version ?: QUIC_VERSION_V1;
	chosen = packet->version;

	for (i = 0; i < count; i++) {
		if (!quic_packet_compatible_versions(versions[i]))
			continue;
		if (preferred == versions[i])
			pref_found = 1;
		if (chosen == versions[i])
			ch_found = 1;
		if (best < versions[i]) /* Track highest offered version. */
			best = versions[i];
	}

	if (!pref_found && !ch_found && !best)
		return -1;

	if (quic_is_serv(sk)) { /* Server prefers preferred version if offered, else chosen. */
		if (pref_found)
			best = preferred;
		else if (ch_found)
			best = chosen;
	} else { /* Client prefers chosen version, else preferred. */
		if (ch_found)
			best = chosen;
		else if (pref_found)
			best = preferred;
	}

	if (packet->version == best)
		return 0;

	/* Change to selected best version. */
	return quic_packet_version_change(sk, &quic_paths(sk)->orig_dcid, best);
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
	struct quic_config *c = quic_config(sk);
	u32 pathmtu, info, taglen;
	struct dst_entry *dst;
	bool reset_timer;

	if (!ip_sk_accept_pmtu(sk))
		return;

	info = clamp(paths->mtu_info, QUIC_PATH_MIN_PMTU, QUIC_PATH_MAX_PMTU);
	/* If PLPMTUD is not enabled, update MSS using the route and ICMP info. */
	if (!c->plpmtud_probe_interval) {
		if (quic_packet_route(sk) < 0)
			return;

		dst = __sk_dst_get(sk);
		dst->ops->update_pmtu(dst, sk, NULL, info, true);
		quic_packet_mss_update(sk, info - packet->hlen);
		/* Retransmit all outstanding data as MTU may have increased. */
		quic_outq_retransmit_mark(sk, QUIC_CRYPTO_APP, 1);
		quic_outq_update_loss_timer(sk);
		quic_outq_transmit(sk);
		return;
	}
	/* PLPMTUD is enabled: adjust to smaller PMTU, subtract headers and AEAD tag.  Also
	 * notify the QUIC path layer for possible state changes and probing.
	 */
	taglen = quic_packet_taglen(packet);
	info = info - packet->hlen - taglen;
	pathmtu = quic_path_pl_toobig(paths, info, &reset_timer);
	if (reset_timer)
		quic_timer_reset(sk, QUIC_TIMER_PMTU, c->plpmtud_probe_interval);
	if (pathmtu)
		quic_packet_mss_update(sk, pathmtu + taglen);
}

/* Handle ICMP Toobig packet and update QUIC socket path MTU. */
static int quic_packet_rcv_err(struct sk_buff *skb)
{
	union quic_addr daddr, saddr;
	struct sock *sk = NULL;
	int ret = 0;
	u32 info;

	/* All we can do is lookup the matching QUIC socket by addresses. */
	quic_get_msg_addrs(skb, &saddr, &daddr);
	sk = quic_sock_lookup(skb, &daddr, &saddr, NULL);
	if (!sk)
		return -ENOENT;

	bh_lock_sock(sk);
	if (quic_is_listen(sk))
		goto out;

	if (quic_get_mtu_info(skb, &info))
		goto out;

	ret = 1; /* Success: update socket path MTU info. */
	quic_paths(sk)->mtu_info = info;
	if (sock_owned_by_user(sk)) {
		/* Socket is in use by userspace context.  Defer MTU processing to later via
		 * tasklet.  Ensure the socket is not dropped before deferral.
		 */
		if (!test_and_set_bit(QUIC_MTU_REDUCED_DEFERRED, &sk->sk_tsq_flags))
			sock_hold(sk);
		goto out;
	}
	/* Otherwise, process the MTU reduction now. */
	quic_packet_rcv_err_pmtu(sk);
out:
	bh_unlock_sock(sk);
	sock_put(sk);
	return ret;
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

/* Extract ALPN data from a TLS ClientHello message.
 *
 * Parses the TLS ClientHello handshake message to find the ALPN (Application Layer Protocol
 * Negotiation) TLS extension. It validates the TLS ClientHello structure, including version,
 * random, session ID, cipher suites, compression methods, and extensions. Once the ALPN
 * extension is found, the ALPN protocols list is extracted and stored in @alpn.
 *
 * Return: 0 on success or no ALPN found, a negative error code on failed parsing.
 */
static int quic_packet_get_alpn(struct quic_data *alpn, u8 *p, u32 len)
{
	int err = -EINVAL, found = 0;
	u64 length, type;

	/* Verify handshake message type (ClientHello) and its length. */
	if (!quic_get_int(&p, &len, &type, 1) || type != TLS_MT_CLIENT_HELLO)
		return err;
	if (!quic_get_int(&p, &len, &length, 3) ||
	    length < TLS_CH_RANDOM_LEN + TLS_CH_VERSION_LEN)
		return err;
	if (len > (u32)length) /* Limit len to handshake message length if larger. */
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

	if (!quic_get_int(&p, &len, &length, 2)) /* Read TLS extensions length (2 bytes). */
		return err;
	if (len > (u32)length) /* Limit len to extensions length if larger. */
		len = length;
	while (len > 4) { /* Iterate over extensions to find ALPN (type TLS_EXT_alpn). */
		if (!quic_get_int(&p, &len, &type, 2))
			break;
		if (!quic_get_int(&p, &len, &length, 2))
			break;
		if (len < (u32)length) /* Incomplete TLS extensions. */
			return 0;
		if (type == TLS_EXT_alpn) { /* Found ALPN extension. */
			len = length;
			found = 1;
			break;
		}
		/* Skip non-ALPN extensions. */
		p += length;
		len -= length;
	}
	if (!found) { /* no ALPN extension found: set alpn->len = 0 and alpn->data = p. */
		quic_data(alpn, p, 0);
		return 0;
	}

	/* Parse ALPN protocols list length (2 bytes). */
	if (!quic_get_int(&p, &len, &length, 2) || length > (u64)len)
		return err;
	quic_data(alpn, p, length); /* Store ALPN protocols list in alpn->data. */
	len = length;
	while (len) { /* Validate ALPN protocols list format. */
		if (!quic_get_int(&p, &len, &length, 1) || length > (u64)len) {
			/* Malformed ALPN entry: set alpn->len = 0 and alpn->data = NULL. */
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
 * This function processes a QUIC Initial packet to extract the ALPN from the TLS ClientHello
 * message inside the QUIC CRYPTO frame. It verifies packet type, version compatibility,
 * decrypts the packet payload, and locates the CRYPTO frame to parse the TLS ClientHello.
 * Finally, it calls quic_packet_get_alpn() to extract the ALPN extension data.
 *
 * Return: 0 on success or no ALPN found, a negative error code on failed parsing.
 */
static int quic_packet_parse_alpn(struct sk_buff *skb, struct quic_data *alpn)
{
	struct quic_skb_cb *cb = QUIC_SKB_CB(skb);
	struct net *net = dev_net(skb->dev);
	struct quic_net *qn = quic_net(net);
	u8 *p = skb->data, *data, type;
	struct quic_conn_id dcid, scid;
	u32 len = skb->len, version;
	struct quic_crypto *crypto;
	struct quic_data token;
	u64 offset, length;
	int err = -EINVAL;

	if (quic_packet_get_version_and_connid(&dcid, &scid, &version, &p, &len))
		return -EINVAL;
	if (!quic_packet_compatible_versions(version))
		return 0;
	/* Only parse Initial packets. */
	type = quic_packet_version_get_type(version, quic_hshdr(skb)->type);
	if (type != QUIC_PACKET_INITIAL)
		return 0;
	if (quic_packet_get_token(&token, &p, &len))
		return -EINVAL;
	if (!quic_get_var(&p, &len, &length) || length > (u64)len)
		return err;
	cb->length = (u16)length;
	/* Copy skb data for restoring in case of decrypt failure. */
	data = kmemdup(skb->data, skb->len, GFP_ATOMIC);
	if (!data)
		return -ENOMEM;

	spin_lock(&qn->lock);
	/* Install initial keys for packet decryption to crypto. */
	crypto = &quic_net(net)->crypto;
	err = quic_crypto_initial_keys_install(crypto, &dcid, version, 1);
	if (err) {
		spin_unlock(&qn->lock);
		goto out;
	}
	cb->number_offset = (u16)(p - skb->data);
	err = quic_crypto_decrypt(crypto, skb);
	if (err) {
		spin_unlock(&qn->lock);
		QUIC_INC_STATS(net, QUIC_MIB_PKT_DECDROP);
		/* Restore original data on decrypt failure. */
		memcpy(skb->data, data, skb->len);
		goto out;
	}
	spin_unlock(&qn->lock);

	QUIC_INC_STATS(net, QUIC_MIB_PKT_DECFASTPATHS);
	cb->resume = 1; /* Mark this packet as already decrypted. */

	/* Find the QUIC CRYPTO frame. */
	p += cb->number_len;
	len = cb->length - cb->number_len - QUIC_TAG_LEN;
	for (; len && !(*p); p++, len--) /* Skip the padding frame. */
		;
	if (!len-- || *p++ != QUIC_FRAME_CRYPTO)
		goto out;
	if (!quic_get_var(&p, &len, &offset) || offset)
		goto out;
	if (!quic_get_var(&p, &len, &length) || length > (u64)len)
		goto out;

	/* Parse the TLS CLIENT_HELLO message. */
	err = quic_packet_get_alpn(alpn, p, length);

out:
	kfree(data);
	return err;
}

/* Extract the Destination Connection ID (DCID) from a QUIC Long header packet. */
int quic_packet_get_dcid(struct quic_conn_id *dcid, struct sk_buff *skb)
{
	u32 plen = skb->len;
	u8 *p = skb->data;
	u64 len;

	if (plen < QUIC_HLEN + QUIC_VERSION_LEN)
		return -EINVAL;
	plen -= (QUIC_HLEN + QUIC_VERSION_LEN);
	p += (QUIC_HLEN + QUIC_VERSION_LEN);

	if (!quic_get_int(&p, &plen, &len, 1) ||
	    len > plen || len > QUIC_CONN_ID_MAX_LEN)
		return -EINVAL;
	quic_conn_id_update(dcid, p, len);
	return 0;
}

/* Determine the QUIC socket associated with an incoming packet. */
static struct sock *quic_packet_get_sock(struct sk_buff *skb)
{
	struct quic_skb_cb *cb = QUIC_SKB_CB(skb);
	struct net *net = dev_net(skb->dev);
	struct quic_conn_id dcid, *conn_id;
	union quic_addr daddr, saddr;
	struct quic_data alpns = {};
	struct sock *sk = NULL;

	if (skb->len < QUIC_HLEN)
		return NULL;

	if (!quic_hdr(skb)->form) { /* Short header path. */
		if (skb->len < QUIC_HLEN + QUIC_CONN_ID_DEF_LEN)
			return NULL;
		/* Fast path: look up QUIC connection by fixed-length DCID
		 * (Currently, only source CIDs of size QUIC_CONN_ID_DEF_LEN are used).
		 */
		conn_id = quic_conn_id_lookup(net, skb->data + QUIC_HLEN,
					      QUIC_CONN_ID_DEF_LEN);
		if (conn_id) {
			cb->seqno = quic_conn_id_number(conn_id);
			return quic_conn_id_sk(conn_id); /* Return associated socket. */
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
		return quic_sock_lookup(skb, &daddr, &saddr, NULL);
	}

	/* Long header path. */
	if (quic_packet_get_dcid(&dcid, skb))
		return NULL;
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
	sk = quic_sock_lookup(skb, &daddr, &saddr, &dcid);
	if (sk)
		return sk;
	/* Final fallback: listener socket lookup
	 * (Used for receiving the first Client Initial packet).
	 */
	if (quic_packet_parse_alpn(skb, &alpns))
		return NULL;
	return quic_listen_sock_lookup(skb, &daddr, &saddr, &alpns);
}

/* Entry point for processing received QUIC packets. */
int quic_packet_rcv(struct sk_buff *skb, u8 err)
{
	struct net *net = dev_net(skb->dev);
	struct sock *sk;

	if (unlikely(err))
		return quic_packet_rcv_err(skb);

	skb_pull(skb, skb_transport_offset(skb));

	/* Look up socket from socket or connection IDs hash tables. */
	sk = quic_packet_get_sock(skb);
	if (!sk)
		goto err;

	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		/* Socket is busy (owned by user context): queue to backlog. */
		if (sk_add_backlog(sk, skb, READ_ONCE(sk->sk_rcvbuf))) {
			QUIC_INC_STATS(net, QUIC_MIB_PKT_RCVDROP);
			bh_unlock_sock(sk);
			sock_put(sk);
			goto err;
		}
		QUIC_INC_STATS(net, QUIC_MIB_PKT_RCVBACKLOGS);
	} else {
		/* Socket not busy: process immediately. */
		QUIC_INC_STATS(net, QUIC_MIB_PKT_RCVFASTPATHS);
		sk->sk_backlog_rcv(sk, skb); /* quic_packet_process(). */
	}
	bh_unlock_sock(sk);
	sock_put(sk);
	return 0;

err:
	kfree_skb(skb);
	return -EINVAL;
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
 * A Retry packet uses a long packet header with a type value of 0x03. It carries an address
 * validation token created by the server. It is used by a server that wishes to perform a retry.
 */
static __maybe_unused int quic_packet_retry_create(struct sock *sk)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
	u8 *p, buf[QUIC_FRAME_BUF_LARGE], tag[QUIC_TAG_LEN];
	struct quic_packet *packet = quic_packet(sk);
	union quic_addr *da = &packet->daddr;
	struct quic_conn_id conn_id;
	struct quichshdr *hdr;
	struct sk_buff *skb;
	u32 len, tlen, hlen;
	struct flowi fl;

	/* Clear routing cache and compute flow route. */
	__sk_dst_reset(sk);
	if (quic_flow_route(sk, da, &packet->saddr, &fl))
		return -EINVAL;

	/* Write token flags into buffer: QUIC_TOKEN_FLAG_RETRY means retry token. */
	quic_put_int(buf, QUIC_TOKEN_FLAG_RETRY, 1);
	/* Generate retry token using client's address and DCID from client initial packet. */
	if (quic_crypto_generate_token(crypto, da, sizeof(*da), &packet->dcid, buf, &tlen))
		return -EINVAL;

	quic_conn_id_generate(&conn_id); /* Generate new SCID for the Retry packet. */
	/* Compute total packet length: header + token + integrity tag. */
	len = QUIC_LONG_HLEN(&conn_id, &packet->scid) + tlen + QUIC_TAG_LEN;
	hlen = quic_encap_len(da) + MAX_HEADER;
	skb = alloc_skb(hlen + len, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;
	skb_reserve(skb, (int)(hlen + len));

	/* Build Long Packet header. */
	hdr = skb_push(skb, len);
	hdr->form = 1;
	hdr->fixed = !quic_outq(sk)->grease_quic_bit;
	hdr->type = quic_packet_version_put_type(packet->version, QUIC_PACKET_RETRY);
	hdr->reserved = 0;
	hdr->pnl = 0;
	skb_reset_transport_header(skb);

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
	if (quic_crypto_get_retry_tag(crypto, skb, &packet->dcid, packet->version, tag)) {
		kfree_skb(skb);
		return -EINVAL;
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
 * A Version Negotiation packet is inherently not version specific. Upon receipt by a client,
 * it will be identified as a Version Negotiation packet based on the Version field having a
 * value of 0.
 *
 * The Version Negotiation packet is a response to a client packet that contains a version that
 * is not supported by the server. It is only sent by servers.
 */
static __maybe_unused int quic_packet_version_create(struct sock *sk)
{
	struct quic_packet *packet = quic_packet(sk);
	union quic_addr *da = &packet->daddr;
	struct quichshdr *hdr;
	struct sk_buff *skb;
	u32 len, hlen, i;
	struct flowi fl;
	u8 *p;

	/* Clear routing cache and compute flow route. */
	__sk_dst_reset(sk);
	if (quic_flow_route(sk, da, &packet->saddr, &fl))
		return -EINVAL;

	/* Compute packet length: header + supported version list. */
	len = QUIC_LONG_HLEN(&packet->dcid, &packet->scid) + QUIC_VERSION_LEN * QUIC_VERSION_NUM;
	hlen = quic_encap_len(da) + MAX_HEADER;
	skb = alloc_skb(hlen + len, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;
	skb_reserve(skb, (int)(hlen + len));

	/* Build Long Packet header. */
	hdr = skb_push(skb, len);
	hdr->form = 1;
	hdr->fixed = !quic_outq(sk)->grease_quic_bit;
	hdr->type = 0;
	hdr->reserved = 0;
	hdr->pnl = 0;
	skb_reset_transport_header(skb);

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
 * A stateless reset is provided as an option of last resort for an endpoint that does not have
 * access to the state of a connection. A crash or outage might result in peers continuing to
 * send data to an endpoint that is unable to properly continue the connection. An endpoint MAY
 * send a Stateless Reset in response to receiving a packet that it cannot associate with an
 * active connection.
 */
static __maybe_unused int quic_packet_stateless_reset_create(struct sock *sk)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
	struct quic_packet *packet = quic_packet(sk);
	union quic_addr *da = &packet->daddr;
	u8 *p, token[QUIC_CONN_ID_TOKEN_LEN];
	struct sk_buff *skb;
	struct flowi fl;
	u32 len, hlen;

	/* Clear routing cache and compute flow route. */
	__sk_dst_reset(sk);
	if (quic_flow_route(sk, da, &packet->saddr, &fl))
		return -EINVAL;

	/* Generate stateless reset token from DCID in the packet received. */
	if (quic_crypto_generate_stateless_reset_token(crypto, packet->dcid.data,
						       packet->dcid.len, token,
						       QUIC_CONN_ID_TOKEN_LEN))
		return -EINVAL;

	len = QUIC_STATELESS_RESET_DEF_LEN;
	hlen = quic_encap_len(da) + MAX_HEADER;
	skb = alloc_skb(hlen + len, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;
	skb_reserve(skb, (int)(hlen + len));

	p = skb_push(skb, len);
	/* Write Unpredictable Bits. */
	get_random_bytes(p, len);
	skb_reset_transport_header(skb);

	/* Build Short Packet header. */
	quic_hdr(skb)->form = 0;
	quic_hdr(skb)->fixed = 1;

	/* Write end of packet with stateless reset token. */
	p += (len - QUIC_CONN_ID_TOKEN_LEN);
	quic_put_data(p, token, QUIC_CONN_ID_TOKEN_LEN);

	/* Transmit the Stateless Reset packet. */
	quic_lower_xmit(sk, skb, da, &fl);
	return 0;
}

static int quic_packet_listen_process(struct sock *sk, struct sk_buff *skb)
{
	kfree_skb(skb);
	return -EOPNOTSUPP;
}

static int quic_packet_handshake_process(struct sock *sk, struct sk_buff *skb)
{
	kfree_skb(skb);
	return -EOPNOTSUPP;
}

static int quic_packet_app_process(struct sock *sk, struct sk_buff *skb)
{
	kfree_skb(skb);
	return -EOPNOTSUPP;
}

int quic_packet_process(struct sock *sk, struct sk_buff *skb)
{
	if (quic_is_closed(sk)) {
		kfree_skb(skb);
		return 0;
	}

	if (quic_is_listen(sk))
		return quic_packet_listen_process(sk, skb);

	if (quic_hdr(skb)->form)
		return quic_packet_handshake_process(sk, skb);

	return quic_packet_app_process(sk, skb);
}

/* Make these fixed for easy coding. */
#define QUIC_PACKET_NUMBER_LEN	4
#define QUIC_PACKET_LENGTH_LEN	4

#define QUIC_MAX_ECN_PROBES	3

static u8 *quic_packet_pack_frames(struct sock *sk, struct sk_buff *skb,
				   struct quic_packet_sent *sent, u16 off)
{
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_packet *packet = quic_packet(sk);
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_skb_cb *cb = QUIC_SKB_CB(skb);
	u32 now = jiffies_to_usecs(jiffies);
	struct quic_frame *frame, *next;
	struct quic_frame_frag *frag;
	struct quic_pnspace *space;
	u8 *p = skb->data + off;
	s64 number;
	u16 i = 0;

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
		p = quic_put_data(p, frame->data, frame->size);
		for (frag = frame->flist; frag; frag = frag->next)
			p = quic_put_data(p, frag->data, frag->size);
		pr_debug("%s: num: %llu, type: %u, packet_len: %u, frame_len: %u, level: %u\n",
			 __func__, number, frame->type, skb->len, frame->len, packet->level);
		if (!frame->ack_eliciting || quic_frame_ping(frame->type)) {
			/* Skip non-ACK-eliciting or ping frames for tracking. */
			quic_frame_put(frame);
			continue;
		}
		if (frame->number < 0) {
			/* First time sending: record packet number and adjust unsent byte count. */
			frame->number = number;
			outq->unsent_bytes -= frame->bytes;
		}
		quic_outq_transmitted_tail(sk, frame); /* Move frame to transmitted queue. */
		/* Hold frame in sent packet record. */
		sent->frame_array[i++] = quic_frame_get(frame);
	}

	/* Track bytes sent before address validation to respect amplification limits for server. */
	if (quic_is_serv(sk) && !paths->validated)
		paths->ampl_sndlen += skb->len + quic_packet_taglen(packet);

	/* Reset path validation timer if handshake is done and we're not currently probing an
	 * alternate path. After handshake, the timer may trigger PATH_CHALLENGE frames for
	 * continued path validation, which should be suppressed if we've just sent ACK-eliciting
	 * data to avoid unnecessary probes.
	 */
	if (quic_is_established(sk) && !quic_path_alt_state(paths, QUIC_PATH_ALT_PROBING))
		quic_timer_reset_path(sk);

	/* Update the last sent timestamp if this packet is ACK-eliciting.  This is important for
	 * loss detection and PTO (Probe Timeout) logic.
	 */
	if (packet->ack_eliciting)
		space->last_sent_time = now;

	if (!sent) /* If the packet doesn't need tracking for ACK or loss detection, we're done. */
		return p;

	/* rfc9000#section-13.4.2:
	 *
	 * To perform ECN validation for a new path:
	 *
	 * The endpoint sets an ECT(0) codepoint in the IP header of early outgoing packets sent
	 * on a new path to the peer.
	 */
	if (!packet->level && paths->ecn_probes < QUIC_MAX_ECN_PROBES) {
		paths->ecn_probes++;
		cb->ecn = INET_ECN_ECT_0;
		sent->ecn = INET_ECN_ECT_0;
	}
	/* Fill metadata for this sent packet.
	 * Convert CRYPTO level to PN space level since 0-RTT and 1-RTT share PN space.
	 */
	sent->number = number;
	sent->sent_time = now;
	sent->frame_len = packet->frame_len;
	sent->level = (packet->level % QUIC_CRYPTO_EARLY);

	space->inflight += sent->frame_len;
	outq->inflight += sent->frame_len;
	/* Append packet to sent list for loss and ACK tracking. */
	quic_outq_packet_sent_tail(sk, sent);

	/* Call cong.on_packet_sent() where it does pacing time update. */
	quic_cong_on_packet_sent(quic_cong(sk), sent->sent_time, sent->frame_len, number);
	/* Refresh loss detection timer after sending data. */
	quic_outq_update_loss_timer(sk);
	return p;
}

static struct quic_packet_sent *quic_packet_sent_alloc(u16 frames)
{
	u32 len = frames * sizeof(struct quic_frame *);
	struct quic_packet_sent *sent;

	sent = kzalloc(sizeof(*sent) + len, GFP_ATOMIC);
	if (sent)
		sent->frames = frames;

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
 * An Initial packet uses long headers with a type value of 0x00. It carries the first CRYPTO
 * frames sent by the client and server to perform key exchange, and it carries ACK frames in
 * either direction.
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
 * A Handshake packet uses long headers with a type value of 0x02, followed by the Length and
 * Packet Number fields. The first byte contains the Reserved and Packet Number Length bits. It is
 * used to carry cryptographic handshake messages and acknowledgments from the server and client.
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
 * A 0-RTT packet uses long headers with a type value of 0x01, followed by the Length and Packet
 * Number fields. The first byte contains the Reserved and Packet Number Length bits. A 0-RTT
 * packet is used to carry "early" data from the client to the server as part of the first flight,
 * prior to handshake completion.
 */
static struct sk_buff *quic_packet_handshake_create(struct sock *sk)
{
	struct quic_conn_id_set *dest = quic_dest(sk), *source = quic_source(sk);
	struct quic_packet *packet = quic_packet(sk);
	u8 type, fixed = 1, level = packet->level;
	struct quic_packet_sent *sent = NULL;
	struct quic_conn_id *active;
	u32 len, hlen, plen = 0;
	struct quichshdr *hdr;
	struct sk_buff *skb;
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

	len = packet->len;
	if (packet->ack_eliciting) {
		/* rfc9000#section-14.1:
		 *
		 * A client MUST expand the payload of all UDP datagrams carrying Initial packets
		 * to at least the smallest allowed maximum datagram size of 1200 bytes by adding
		 * PADDING frames to the Initial packet or by coalescing the Initial packet.
		 * Similarly, a server MUST expand the payload of all UDP datagrams carrying
		 * ack-eliciting Initial packets to at least the smallest allowed maximum datagram
		 * size of 1200 bytes.
		 */
		hlen = QUIC_MIN_UDP_PAYLOAD - packet->taglen[1];
		if (level == QUIC_CRYPTO_INITIAL && len < hlen) {
			len = hlen;
			plen = len - packet->len;
		}
	}
	if (packet->frames) {
		/* If there are ack-eliciting frames (not including PING), create packet_sent
		 * for acknowledge and loss detection.
		 */
		sent = quic_packet_sent_alloc(packet->frames);
		if (!sent) { /* Move pending frames back to the outqueue. */
			quic_outq_retransmit_list(sk, &packet->frame_list);
			return NULL;
		}
	}

	/* Allocate skb with space for header + payload + AEAD taglen of Long Packet. */
	hlen = packet->hlen + MAX_HEADER;
	skb = alloc_skb(hlen + len + packet->taglen[1], GFP_ATOMIC);
	if (!skb) {
		kfree(sent);
		quic_outq_retransmit_list(sk, &packet->frame_list);
		return NULL;
	}
	skb->ignore_df = packet->ipfragok;
	skb_reserve(skb, (int)(hlen + len));

	/* Build Long Packet header. */
	hdr = skb_push(skb, len);
	hdr->form = 1;
	hdr->fixed = fixed;
	hdr->type = quic_packet_version_put_type(packet->version, type);
	hdr->reserved = 0;
	hdr->pnl = QUIC_PACKET_NUMBER_LEN - 1;
	skb_reset_transport_header(skb);

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
	if (level == QUIC_CRYPTO_INITIAL) { /* Only Initial packet carries tokens. */
		hlen = 0;
		if (!quic_is_serv(sk)) /* Only clients send tokens. */
			hlen = quic_token(sk)->len;
		p = quic_put_var(p, hlen);
		p = quic_put_data(p, quic_token(sk)->data, hlen);
	}

	/* Write Length. */
	off = (u16)(p + QUIC_PACKET_LENGTH_LEN - skb->data);
	p = quic_put_varint(p, len - off + QUIC_TAG_LEN, QUIC_PACKET_LENGTH_LEN);

	/* Pack Packet Number and actual frames starting at offset 'off'. */
	p = quic_packet_pack_frames(sk, skb, sent, off);
	if (plen) /* Set padding to zero. */
		memset(p, 0, plen);
	return skb;
}

/* Ensures the packet number is within the valid range. */
static int quic_packet_number_check(struct sock *sk)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_pnspace *space;

	/* Check if the next packet number is within the allowed range. */
	space = quic_pnspace(sk, packet->level);
	if (space->next_pn + 1 <= QUIC_PN_MAP_MAX_PN)
		return 0;

	/* Move pending frames back to the outqueue. */
	quic_outq_retransmit_list(sk, &packet->frame_list);

	/* rfc9000#section-12.3:
	 *
	 * If the packet number for sending reaches 262-1, the sender MUST close the
	 * connection without sending a CONNECTION_CLOSE frame or any further packets.
	 */
	if (!quic_is_closed(sk)) {
		struct quic_connection_close close = {};

		/* Notify application that the connection is being closed. */
		quic_inq_event_recv(sk, QUIC_EVENT_CONNECTION_CLOSE, &close);
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
 * A 1-RTT packet uses a short packet header. It is used after the version and 1-RTT keys are
 * negotiated.
 */
static struct sk_buff *quic_packet_app_create(struct sock *sk)
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
		/* If there are ack-eliciting frames (not including PING), create packet_sent
		 * for acknowledge and loss detection.
		 */
		sent = quic_packet_sent_alloc(packet->frames);
		if (!sent) { /* Move pending frames back to the outqueue. */
			quic_outq_retransmit_list(sk, &packet->frame_list);
			return NULL;
		}
	}

	/* Allocate skb with space for header + payload + AEAD taglen of Short Packet. */
	len = packet->len;
	hlen = packet->hlen + MAX_HEADER;
	skb = alloc_skb(hlen + len + packet->taglen[0], GFP_ATOMIC);
	if (!skb) { /* Move pending frames back to the outqueue. */
		kfree(sent);
		quic_outq_retransmit_list(sk, &packet->frame_list);
		return NULL;
	}
	skb->ignore_df = packet->ipfragok;
	skb_reserve(skb, (int)(hlen + len));

	/* Build Short Packet header. */
	hdr = skb_push(skb, len);
	hdr->form = 0;
	hdr->fixed = !quic_outq(sk)->grease_quic_bit;
	hdr->spin = 0;
	hdr->reserved = 0;
	hdr->pnl = QUIC_PACKET_NUMBER_LEN - 1;
	skb_reset_transport_header(skb);

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
	packet->mss[0] = (u16)mss;

	/* Update congestion control with new payload space (excluding tag). */
	quic_cong_set_mss(cong, packet->mss[0] - packet->taglen[0]);
	quic_outq_sync_window(sk, cong->window);

	/* Limit MSS for DATAGRAM frame packets to the max datagram frame size. */
	if (outq->max_datagram_frame_size && mss > outq->max_datagram_frame_size)
		mss = outq->max_datagram_frame_size;
	packet->mss[1] = (u16)mss;
}

/* Perform routing for the QUIC packet on the specified path, update header length and MSS
 * accordingly, reset path and start PMTU timer.
 */
int quic_packet_route(struct sock *sk)
{
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_packet *packet = quic_packet(sk);
	struct quic_config *c = quic_config(sk);
	union quic_addr *sa, *da;
	u32 pmtu;
	int err;

	da = quic_path_daddr(paths, packet->path);
	sa = quic_path_saddr(paths, packet->path);
	err = quic_flow_route(sk, da, sa, &paths->fl);
	if (err)
		return err;

	packet->hlen = quic_encap_len(da);
	pmtu = min_t(u32, dst_mtu(__sk_dst_get(sk)), QUIC_PATH_MAX_PMTU);
	quic_packet_mss_update(sk, pmtu - packet->hlen);

	quic_path_pl_reset(paths);
	quic_timer_reset(sk, QUIC_TIMER_PMTU, c->plpmtud_probe_interval);
	return 0;
}

/* Configure the QUIC packet header and routing based on encryption level and path. */
int quic_packet_config(struct sock *sk, u8 level, u8 path)
{
	struct quic_conn_id_set *dest = quic_dest(sk), *source = quic_source(sk);
	struct quic_packet *packet = quic_packet(sk);
	struct quic_config *c = quic_config(sk);
	u32 hlen = QUIC_HLEN;

	/* If packet already has data, no need to reconfigure. */
	if (!quic_packet_empty(packet))
		return 0;

	packet->ack_eliciting = 0;
	packet->frame_len = 0;
	packet->ipfragok = 0;
	packet->padding = 0;
	packet->frames = 0;
	hlen += QUIC_PACKET_NUMBER_LEN; /* Packet number length. */
	hlen += quic_conn_id_choose(dest, path)->len; /* DCID length. */
	if (level) {
		hlen += 1; /* Length byte for DCID. */
		hlen += 1 + quic_conn_id_active(source)->len; /* Length byte + SCID length. */
		if (level == QUIC_CRYPTO_INITIAL) /* Include token for Initial packets. */
			hlen += quic_var_len(quic_token(sk)->len) + quic_token(sk)->len;
		hlen += QUIC_VERSION_LEN; /* Version length. */
		hlen += QUIC_PACKET_LENGTH_LEN; /* Packet length field length. */
		/* Allow fragmentation if PLPMTUD is enabled, as it no longer relies on ICMP
		 * Toobig messages to discover the path MTU.
		 */
		packet->ipfragok = !!c->plpmtud_probe_interval;
	}
	packet->level = level;
	packet->len = (u16)hlen;
	packet->overhead = (u8)hlen;

	if (packet->path != path) { /* If the path changed, update and reset routing cache. */
		packet->path = path;
		__sk_dst_reset(sk);
	}

	/* Perform routing and MSS update for the configured packet. */
	if (quic_packet_route(sk) < 0)
		return -1;
	return 0;
}

static void quic_packet_encrypt_done(struct sk_buff *skb, int err)
{
	if (err) {
		QUIC_INC_STATS(sock_net(skb->sk), QUIC_MIB_PKT_ENCDROP);
		kfree_skb(skb);
		pr_debug("%s: err: %d\n", __func__, err);
		return;
	}

	/* Encryption succeeded: queue the encrypted skb for asynchronous transmission. */
	quic_outq_encrypted_tail(skb->sk, skb);
}

/* Coalescing Packets. */
static int quic_packet_bundle(struct sock *sk, struct sk_buff *skb)
{
	struct quic_skb_cb *head_cb, *cb = QUIC_SKB_CB(skb);
	struct quic_packet *packet = quic_packet(sk);
	struct sk_buff *p;

	if (!packet->head) { /* First packet to bundle: initialize the head. */
		packet->head = skb;
		cb->last = skb;
		goto out;
	}

	/* If bundling would exceed MSS, flush the current bundle. */
	if (packet->head->len + skb->len >= packet->mss[0]) {
		quic_packet_flush(sk);
		packet->head = skb;
		cb->last = skb;
		goto out;
	}
	/* Bundle it and update metadata for the aggregate skb. */
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
	/* rfc9000#section-12.2:
	 *   Packets with a short header (Section 17.3) do not contain a Length field and so
	 *   cannot be followed by other packets in the same UDP datagram.
	 *
	 * so Return 1 to flush if it is a Short header packet.
	 */
	return !cb->level;
}

/* Transmit a QUIC packet, possibly encrypting and bundling it. */
int quic_packet_xmit(struct sock *sk, struct sk_buff *skb)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_skb_cb *cb = QUIC_SKB_CB(skb);
	struct net *net = sock_net(sk);
	int err;

	/* Associate skb with sk to ensure sk is valid during async encryption completion. */
	WARN_ON(!skb_set_owner_sk_safe(skb, sk));

	/* Skip encryption if taglen == 0 (e.g., disable_1rtt_encryption). */
	if (!packet->taglen[quic_hdr(skb)->form])
		goto xmit;

	cb->crypto_done = quic_packet_encrypt_done;
	err = quic_crypto_encrypt(quic_crypto(sk, packet->level), skb);
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
int quic_packet_create(struct sock *sk)
{
	struct quic_packet *packet = quic_packet(sk);
	struct sk_buff *skb;
	int err;

	err = quic_packet_number_check(sk);
	if (err)
		goto err;

	if (packet->level)
		skb = quic_packet_handshake_create(sk);
	else
		skb = quic_packet_app_create(sk);
	if (!skb) {
		err = -ENOMEM;
		goto err;
	}

	err = quic_packet_xmit(sk, skb);
	if (err && err != -EINPROGRESS)
		goto err;

	/* Return 1 if at least one ACK-eliciting (non-PING) frame was sent. */
	return !!packet->frames;
err:
	pr_debug("%s: err: %d\n", __func__, err);
	return 0;
}

/* Flush any coalesced/bundled QUIC packets. */
void quic_packet_flush(struct sock *sk)
{
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_packet *packet = quic_packet(sk);

	if (packet->head) {
		quic_lower_xmit(sk, packet->head,
				quic_path_daddr(paths, packet->path), &paths->fl);
		packet->head = NULL;
	}
}

/* Append a frame to the tail of the current QUIC packet. */
int quic_packet_tail(struct sock *sk, struct quic_frame *frame)
{
	struct quic_packet *packet = quic_packet(sk);
	u8 taglen;

	/* Reject frame if it doesn't match the packet's encryption level or path, or if
	 * padding is already in place (no further frames should be added).
	 */
	if (frame->level != (packet->level % QUIC_CRYPTO_EARLY) ||
	    frame->path != packet->path || packet->padding)
		return 0;

	/* Check if frame would exceed the current datagram MSS (excluding AEAD tag). */
	taglen = quic_packet_taglen(packet);
	if (packet->len + frame->len > packet->mss[frame->dgram] - taglen) {
		/* If some data has already been added to the packet, bail out. */
		if (packet->len != packet->overhead)
			return 0;
		/* Otherwise, allow IP fragmentation for this packet unless it’s a PING probe. */
		if (!quic_frame_ping(frame->type))
			packet->ipfragok = 1;
	}
	if (frame->padding)
		packet->padding = frame->padding;

	/* Track frames that require retransmission if lost (i.e., ACK-eliciting and non-PING). */
	if (frame->ack_eliciting) {
		packet->ack_eliciting = 1;
		if (!quic_frame_ping(frame->type)) {
			packet->frames++;
			packet->frame_len += frame->len;
		}
	}

	list_move_tail(&frame->list, &packet->frame_list);
	packet->len += frame->len;
	return frame->len;
}

void quic_packet_init(struct sock *sk)
{
	struct quic_packet *packet = quic_packet(sk);

	INIT_LIST_HEAD(&packet->frame_list);
	packet->taglen[0] = QUIC_TAG_LEN;
	packet->taglen[1] = QUIC_TAG_LEN;
	packet->mss[0] = QUIC_TAG_LEN;
	packet->mss[1] = QUIC_TAG_LEN;

	packet->version = QUIC_VERSION_V1;
}
