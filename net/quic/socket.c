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

#include <net/inet_common.h>
#include <net/tls.h>

#include "socket.h"

static DEFINE_PER_CPU(int, quic_memory_per_cpu_fw_alloc);
static unsigned long quic_memory_pressure;
static atomic_long_t quic_memory_allocated;

static void quic_enter_memory_pressure(struct sock *sk)
{
	WRITE_ONCE(quic_memory_pressure, 1);
}

/* Check if a matching request sock already exists. Match is based on
 * source/destination addresses and DCID.
 */
struct quic_request_sock *quic_request_sock_lookup(struct sock *sk)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_request_sock *req;

	list_for_each_entry(req, quic_reqs(sk), list) {
		if (!memcmp(&req->saddr, &packet->saddr, sizeof(req->saddr)) &&
		    !memcmp(&req->daddr, &packet->daddr, sizeof(req->daddr)) &&
		    !quic_conn_id_cmp(&req->dcid, &packet->dcid))
			return req;
	}
	return NULL;
}

/* Create and enqueue a QUIC request sock for a new incoming connection. */
struct quic_request_sock *quic_request_sock_create(struct sock *sk,
						   struct quic_conn_id *odcid,
						   u8 retry, gfp_t gfp)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_request_sock *req;

	if (sk_acceptq_is_full(sk)) /* Refuse if accept queue full. */
		return ERR_PTR(-ENOBUFS);

	req = kmalloc_obj(*req, gfp);
	if (!req)
		return ERR_PTR(-ENOMEM);

	req->version = packet->version;
	req->daddr = packet->daddr;
	req->saddr = packet->saddr;
	req->scid = packet->scid;
	req->dcid = packet->dcid;
	req->orig_dcid = *odcid;
	req->retry = retry;

	skb_queue_head_init(&req->backlog_list);
	req->blen = 0;

	/* Enqueue request into listen socket’s pending list for accept(). */
	list_add_tail(&req->list, quic_reqs(sk));
	sk_acceptq_added(sk);
	return req;
}

int quic_request_sock_backlog_tail(struct sock *sk,
				   struct quic_request_sock *req,
				   struct sk_buff *skb)
{
	/* Use listen sock sk_rcvbuf to limit the request sock's backlog len. */
	if (req->blen + skb->truesize > sk->sk_rcvbuf) {
		QUIC_INC_STATS(sock_net(sk), QUIC_MIB_PKT_RCVDROP);
		kfree_skb(skb);
		return -ENOBUFS;
	}

	__skb_queue_tail(&req->backlog_list, skb);
	req->blen += skb->truesize;
	sk->sk_data_ready(sk);
	return 0;
}

static void quic_request_sock_free(struct sock *sk,
				   struct quic_request_sock *req)
{
	__skb_queue_purge(&req->backlog_list);
	list_del_init(&req->list);
	sk_acceptq_removed(sk);
	kfree(req);
}

/* Check if a matching accept socket exists. This is needed because an accept
 * socket might have been created after this packet was enqueued in the listen
 * socket's backlog.
 */
bool quic_accept_sock_exists(struct sock *sk, struct sk_buff *skb)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_skb_cb *cb = QUIC_SKB_CB(skb);
	bool exist = false;

	/* Skip if packet is newer than the last accept socket creation time.
	 * No matching socket could exist in this case.
	 */
	if (QUIC_SKB_CB(skb)->time >
	    quic_pnspace(sk, QUIC_CRYPTO_INITIAL)->time)
		return exist;

	/* Look up accepted socket matching packet addresses and DCID. */
	local_bh_disable();
	sk = quic_sock_lookup(skb, &packet->saddr, &packet->daddr, skb->sk,
			      &packet->dcid);
	if (!sk)
		goto out;

	/* Found a matching accept socket. Process packet with this socket. */
	bh_lock_sock_nested(sk);
	if (sock_owned_by_user(sk)) {
		/* Socket is busy (owned by user context): queue to backlog. */
		if (sk_add_backlog(sk, skb, READ_ONCE(sk->sk_rcvbuf))) {
			QUIC_INC_STATS(sock_net(sk), QUIC_MIB_PKT_RCVDROP);
			kfree_skb(skb);
		} else {
			cb->backlog = 1;
		}
	} else {
		/* Socket not busy: process immediately. */
		cb->backlog = 0;
		sk->sk_backlog_rcv(sk, skb); /* quic_packet_process(). */
	}
	bh_unlock_sock(sk);
	sock_put(sk);
	exist = true;
out:
	local_bh_enable();
	return exist;
}

/* Lookup a connected QUIC socket based on address and dest connection ID.
 *
 * This function searches the established (non-listening) QUIC socket table for
 * a socket that matches the source and dest addresses and, optionally, the
 * dest connection ID (DCID). The value returned by quic_path_orig_dcid() might
 * be the original dest connection ID from the ClientHello or the Source
 * Connection ID from a Retry packet before.
 *
 * The DCID is provided from a handshake packet when searching by source
 * connection ID fails, such as when the peer has not yet received server's
 * response and updated the DCID.
 *
 * Return: A pointer to the matching connected socket, or NULL if no match is
 * found.
 */
struct sock *quic_sock_lookup(struct sk_buff *skb, union quic_addr *sa,
			      union quic_addr *da, struct sock *usk,
			      struct quic_conn_id *dcid)
{
	struct net *net = sock_net(usk);
	struct quic_path_group *paths;
	struct hlist_nulls_node *node;
	struct quic_shash_head *head;
	struct sock *sk = NULL, *tmp;
	struct quic_conn_id *odcid;
	unsigned int hash;

	hash = quic_sock_hash(net, sa, da);
	head = quic_sock_head(hash);

	rcu_read_lock();
begin:
	sk_nulls_for_each_rcu(tmp, node, &head->head) {
		if (net != sock_net(tmp))
			continue;
		paths = quic_paths(tmp);
		odcid = quic_path_orig_dcid(paths);
		if (quic_cmp_sk_addr(tmp, quic_path_saddr(paths, 0), sa) &&
		    quic_cmp_sk_addr(tmp, quic_path_daddr(paths, 0), da) &&
		    quic_path_usock(paths, 0) == usk &&
		    (!dcid || !quic_conn_id_cmp(odcid, dcid))) {
			sk = tmp;
			break;
		}
	}
	/* If the final nulls value differs from the expected one, restart the
	 * lookup as the node may have been rehashed (e.g., due to connection
	 * migration).
	 */
	if (!sk && get_nulls_value(node) != hash)
		goto begin;

	if (sk && unlikely(!refcount_inc_not_zero(&sk->sk_refcnt)))
		sk = NULL;
	rcu_read_unlock();
	return sk;
}

/* Find the listening QUIC socket for an incoming packet.
 *
 * This function searches the QUIC socket table for a listening socket that
 * matches the dest address and port, and the ALPN(s) if presented in the
 * ClientHello.  If multiple listening sockets are bound to the same address,
 * port, and ALPN(s) (e.g., via SO_REUSEPORT), this function selects a socket
 * from the reuseport group.
 *
 * Return: A pointer to the matching listening socket, or NULL if no match is
 * found.
 */
struct sock *quic_listen_sock_lookup(struct sk_buff *skb, union quic_addr *sa,
				     union quic_addr *da,
				     struct quic_data *alpns)
{
	struct net *net = sock_net(skb->sk);
	struct hlist_nulls_node *node;
	struct sock *sk = NULL, *tmp;
	struct quic_shash_head *head;
	struct quic_data alpn;
	union quic_addr *a;
	u32 hash, len;
	u64 length;
	u8 *p;

	hash = quic_listen_sock_hash(net, ntohs(sa->v4.sin_port));
	head = quic_listen_sock_head(hash);

	rcu_read_lock();
	if (!alpns->len) { /* No ALPNs or parse failed */
		sk_nulls_for_each_rcu(tmp, node, &head->head) {
			/* If alpns->data != NULL, TLS parsing succeeded but no
			 * ALPN was found.  In this case, only match sockets
			 * that have no ALPN set.
			 */
			a = quic_path_saddr(quic_paths(tmp), 0);
			if (net == sock_net(tmp) &&
			    quic_cmp_sk_addr(tmp, a, sa) &&
			    quic_path_usock(quic_paths(tmp), 0) == skb->sk &&
			    (!alpns->data || !quic_alpn(tmp)->len)) {
				if (!quic_is_any_addr(a)) {
					sk = tmp;
					break; /* Prefer specific addr match. */
				}
				/* Prefer ipv4 ANY over ipv6 ANY for v4 addr. */
				if (!sk || a->sa.sa_family == sa->sa.sa_family)
					sk = tmp;
			}
		}
		/* No need to check get_nulls_value(node) != hash for !sk, as
		 * hashtable size is fixed and a listen sk can not rehashed.
		 */
		goto out;
	}

	/* ALPN present: loop through each ALPN entry. */
	for (p = alpns->data, len = alpns->len; len;
	     len -= length, p += length) {
		quic_get_int(&p, &len, &length, 1);
		quic_data(&alpn, p, length);
		sk_nulls_for_each_rcu(tmp, node, &head->head) {
			a = quic_path_saddr(quic_paths(tmp), 0);
			if (net == sock_net(tmp) &&
			    quic_cmp_sk_addr(tmp, a, sa) &&
			    quic_path_usock(quic_paths(tmp), 0) == skb->sk &&
			    quic_data_has(quic_alpn(tmp), &alpn)) {
				if (!quic_is_any_addr(a)) {
					sk = tmp;
					break;
				}
				if (!sk || a->sa.sa_family == sa->sa.sa_family)
					sk = tmp;
			}
		}
		/* No need to check get_nulls_value(node) != hash for !sk, as
		 * hashtable size is fixed and a listen sk can not rehashed.
		 */
		if (sk)
			break;
	}
out:
	if (sk && sk->sk_reuseport)
		sk = reuseport_select_sock(sk, quic_addr_hash(net, da), skb, 1);

	if (sk && unlikely(!refcount_inc_not_zero(&sk->sk_refcnt)))
		sk = NULL;
	rcu_read_unlock();
	return sk;
}

static void quic_write_space(struct sock *sk)
{
	__poll_t mask = EPOLLOUT | EPOLLWRNORM | EPOLLWRBAND;
	struct socket_wq *wq;

	/* Do not check sock_writeable(). Also wakes stream-open waiters
	 * blocked on stream limits, where sock_writeable() may be false.
	 */
	rcu_read_lock();
	wq = rcu_dereference(sk->sk_wq);
	if (skwq_has_sleeper(wq))
		wake_up_interruptible_sync_poll(&wq->wait, mask);
	sk_wake_async_rcu(sk, SOCK_WAKE_SPACE, POLL_OUT);
	rcu_read_unlock();
}

/* Apply QUIC transport parameters to subcomponents of the socket. */
static void quic_sock_apply_transport_param(struct sock *sk,
					    struct quic_transport_param *p)
{
	struct quic_conn_id_set *id_set =
		p->remote ? quic_source(sk) : quic_dest(sk);

	quic_inq_set_param(sk, p);
	quic_outq_set_param(sk, p);
	quic_conn_id_set_param(id_set, p);
	quic_path_set_param(quic_paths(sk), p);
	quic_stream_set_param(quic_streams(sk), p, quic_is_serv(sk));
}

/* Fetch QUIC transport parameters from subcomponents of the socket. */
static void quic_sock_fetch_transport_param(struct sock *sk,
					    struct quic_transport_param *p)
{
	struct quic_conn_id_set *id_set =
		p->remote ? quic_source(sk) : quic_dest(sk);

	quic_inq_get_param(sk, p);
	quic_outq_get_param(sk, p);
	quic_conn_id_get_param(id_set, p);
	quic_path_get_param(quic_paths(sk), p);
	quic_stream_get_param(quic_streams(sk), p);
}

static void quic_sock_destruct(struct sock *sk)
{
	u8 i;

	/* Deferred crypto free for async encryption/decryption. */
	for (i = 0; i < QUIC_CRYPTO_MAX; i++)
		quic_crypto_free(quic_crypto(sk, i));

	/* Deferred ALPN free for RCU readers in quic_listen_sock_lookup(). */
	quic_data_free(quic_alpn(sk));

	quic_sk_destruct(sk);
}

static int quic_init_sock(struct sock *sk)
{
	struct quic_transport_param *p = &quic_default_param;
	u8 i;

	sk->sk_destruct = quic_sock_destruct;
	sk->sk_write_space = quic_write_space;
	sock_set_flag(sk, SOCK_USE_WRITE_QUEUE);

	sk_sockets_allocated_inc(sk);
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);
	INIT_LIST_HEAD(quic_reqs(sk));

	quic_conn_id_set_init(quic_source(sk), true);
	quic_conn_id_set_init(quic_dest(sk), false);
	quic_cong_init(quic_cong(sk));

	quic_sock_apply_transport_param(sk, p);

	quic_outq_init(sk);
	quic_inq_init(sk);
	quic_timer_init(sk);
	quic_packet_init(sk);

	if (quic_stream_init(quic_streams(sk)))
		return -ENOMEM;

	for (i = 0; i < QUIC_PNSPACE_MAX; i++) {
		if (quic_pnspace_init(quic_pnspace(sk, i)))
			return -ENOMEM;
	}

	return 0;
}

static void quic_destroy_sock(struct sock *sk)
{
	u8 i;

	quic_outq_free(sk);
	quic_inq_free(sk);
	quic_timer_free(sk);

	for (i = 0; i < QUIC_PNSPACE_MAX; i++)
		quic_pnspace_free(quic_pnspace(sk, i));

	quic_path_unbind(sk, quic_paths(sk), 0);
	quic_path_unbind(sk, quic_paths(sk), 1);

	quic_conn_id_set_free(quic_source(sk));
	quic_conn_id_set_free(quic_dest(sk));

	quic_stream_free(quic_streams(sk));

	quic_data_free(quic_ticket(sk));
	quic_data_free(quic_token(sk));

	sk_sockets_allocated_dec(sk);
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);
}

static int quic_bind(struct sock *sk, struct sockaddr_unsized *addr,
		     int addr_len)
{
	struct quic_path_group *paths = quic_paths(sk);
	union quic_addr *sa, a;
	int err = -EINVAL;

	lock_sock(sk);

	if (quic_path_saddr(paths, 0)->v4.sin_port ||
	    quic_get_user_addr(sk, &a, (struct sockaddr *)addr, addr_len, true))
		goto out;

	sa = quic_path_saddr(paths, 0);

	quic_path_set_saddr(paths, 0, &a);
	err = quic_path_bind(sk, paths, 0);
	if (err) {
		memset(sa, 0, sizeof(*sa));
		goto out;
	}
	quic_set_sk_addr(sk, sa, true);

out:
	release_sock(sk);
	return err;
}

static int quic_connect(struct sock *sk, struct sockaddr_unsized *addr,
			int addr_len)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
	struct quic_conn_id_set *source = quic_source(sk);
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_conn_id_set *dest = quic_dest(sk);
	struct quic_packet *packet = quic_packet(sk);
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_conn_id conn_id = {}, *active;
	struct quic_inqueue *inq = quic_inq(sk);
	gfp_t gfp = GFP_KERNEL;
	union quic_addr *sa, a;
	int err = -EINVAL;

	lock_sock(sk);
	if (!sk_unhashed(sk) ||
	    quic_get_user_addr(sk, &a, (struct sockaddr *)addr, addr_len,
			       false))
		goto out;

	/* Set destination address and resolve route (may also auto-set source
	 * address).
	 */
	quic_path_set_daddr(paths, 0, &a);
	err = quic_packet_route(sk);
	if (err)
		goto out;
	quic_set_sk_addr(sk, &a, false);

	sa = quic_path_saddr(paths, 0);
	if (!sa->v4.sin_port) { /* Auto-bind if not already bound. */
		err = quic_path_bind(sk, paths, 0);
		if (err)
			goto out;
		quic_set_sk_addr(sk, sa, true);
	}

	/* Generate and add destination and source connection IDs. */
	quic_conn_id_generate(&conn_id);
	err = quic_conn_id_add(dest, &conn_id, 0, NULL, gfp);
	if (err)
		goto out;
	/* Save original DCID for validating server's transport parameters. */
	paths->orig_dcid = conn_id;
	quic_conn_id_generate(&conn_id);
	err = quic_conn_id_add(source, &conn_id, 0, sk, gfp);
	if (err)
		goto free;
	active = quic_conn_id_active(dest);

	/* Install initial encryption keys for handshake. */
	err = quic_crypto_set_cipher(crypto, TLS_CIPHER_AES_GCM_128);
	if (err)
		goto free;
	if (outq->version)
		packet->version = outq->version;
	err = quic_crypto_initial_keys_install(crypto, active, packet->version,
					       false);
	if (err)
		goto free;
	err = quic_crypto_set_token_secret(crypto);
	if (err)
		goto free;

	/* Add socket to hash table, change state to ESTABLISHING, and start
	 * idle timer.
	 */
	quic_set_state(sk, QUIC_SS_ESTABLISHING);
	err = sk->sk_prot->hash(sk);
	if (err)
		goto free;
	quic_timer_start(sk, QUIC_TIMER_IDLE, inq->timeout);
	quic_timer_start(sk, QUIC_TIMER_PATH, paths->keepalive_interval);
out:
	release_sock(sk);
	return err;
free:
	quic_set_state(sk, QUIC_SS_CLOSED);
	quic_conn_id_set_free(source);
	quic_conn_id_set_free(dest);
	quic_crypto_free(crypto);
	goto out;
}

static int quic_hash(struct sock *sk)
{
	struct quic_path_group *npaths, *paths = quic_paths(sk);
	struct quic_data *alpns = quic_alpn(sk);
	struct net *net = sock_net(sk);
	struct hlist_nulls_node *node;
	struct quic_shash_head *head;
	union quic_addr *sa, *da;
	struct sock *nsk;
	int err = 0, any;
	u32 hash;

	sa = quic_path_saddr(paths, 0);
	da = quic_path_daddr(paths, 0);
	if (!quic_is_listen(sk)) {
		/* Hash a regular socket with source and dest addrs/ports. */
		head = quic_sock_head(quic_sock_hash(net, sa, da));
		spin_lock_bh(&head->lock);
		sock_set_flag(sk, SOCK_RCU_FREE);
		__sk_nulls_add_node_rcu(sk, &head->head);
		spin_unlock_bh(&head->lock);
		return 0;
	}

	if (quic_alpn(sk)->data)
		static_branch_inc(&quic_alpn_demux_key);

	/* Hash a listen socket with source port only. */
	hash = quic_listen_sock_hash(net, ntohs(sa->v4.sin_port));
	head = quic_listen_sock_head(hash);
	spin_lock_bh(&head->lock);

	any = quic_is_any_addr(sa);
	sk_nulls_for_each(nsk, node, &head->head) {
		if (net != sock_net(nsk))
			continue;
		npaths = quic_paths(nsk);
		if (memcmp(quic_path_saddr(npaths, 0), sa, sizeof(*sa)))
			continue;
		if (quic_path_usock(paths, 0) != quic_path_usock(npaths, 0))
			continue;

		/* Take the ALPNs into account, which allows directing the
		 * request to different listening sockets based on the ALPNs.
		 */
		if (!quic_data_cmp(alpns, quic_alpn(nsk))) {
			err = -EADDRINUSE;
			if (!sk->sk_reuseport || !nsk->sk_reuseport)
				goto out;

			/* Support SO_REUSEPORT: allow multiple sockets with
			 * same addr/port/ALPNs.
			 */
			err = reuseport_add_sock(sk, nsk, any);
			if (err)
				goto out;
			sock_set_flag(sk, SOCK_RCU_FREE);
			__sk_nulls_add_node_rcu(sk, &head->head);
			goto out;
		}
		/* If ALPNs partially match, also consider address in use. */
		if (quic_data_match(alpns, quic_alpn(nsk))) {
			err = -EADDRINUSE;
			goto out;
		}
	}

	if (sk->sk_reuseport) { /* Allocate reuseport group if enabled. */
		err = reuseport_alloc(sk, any);
		if (err)
			goto out;
	}
	sock_set_flag(sk, SOCK_RCU_FREE);
	__sk_nulls_add_node_rcu(sk, &head->head);

out:
	spin_unlock_bh(&head->lock);

	if (err && quic_alpn(sk)->data)
		static_branch_dec(&quic_alpn_demux_key);
	return err;
}

static void quic_unhash(struct sock *sk)
{
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_request_sock *req, *tmp;
	struct net *net = sock_net(sk);
	struct quic_shash_head *head;
	union quic_addr *sa, *da;
	u32 hash;

	if (sk_unhashed(sk))
		return;

	sa = quic_path_saddr(paths, 0);
	da = quic_path_daddr(paths, 0);
	if (quic_is_listen(sk)) {
		/* Unhash listening socket; drop pending requests. */
		list_for_each_entry_safe(req, tmp, quic_reqs(sk), list)
			quic_request_sock_free(sk, req);
		if (quic_alpn(sk)->data)
			static_branch_dec(&quic_alpn_demux_key);
		hash = quic_listen_sock_hash(net, ntohs(sa->v4.sin_port));
		head = quic_listen_sock_head(hash);
		goto out;
	}
	head = quic_sock_head(quic_sock_hash(net, sa, da));

out:
	spin_lock_bh(&head->lock);
	/* If socket was part of a reuseport group, detach it. */
	if (rcu_access_pointer(sk->sk_reuseport_cb))
		reuseport_detach_sock(sk);
	__sk_nulls_del_node_init_rcu(sk);
	spin_unlock_bh(&head->lock);
}

static inline void quic_copy_common(void *dst, size_t dlen, const void *src,
				    size_t slen)
{
	size_t len = min_t(size_t, dlen, slen);

	if (!len)
		return;
	memcpy(dst, src, len);
}

#define QUIC_MSG_STREAM_FLAGS \
	(MSG_QUIC_STREAM_NEW | MSG_QUIC_STREAM_FIN | MSG_QUIC_STREAM_UNI | \
	 MSG_QUIC_STREAM_DONTWAIT | MSG_QUIC_STREAM_SNDBLOCK)

#define QUIC_MSG_FLAGS \
	(QUIC_MSG_STREAM_FLAGS | MSG_BATCH | MSG_MORE | MSG_DONTWAIT | \
	 MSG_NOSIGNAL | MSG_WAITALL | MSG_QUIC_DATAGRAM)

/* Parse control messages for stream or handshake metadata from msghdr. */
static int quic_msghdr_parse(struct sock *sk, struct msghdr *msg,
			     struct quic_handshake_info *hinfo,
			     struct quic_stream_info *sinfo,
			     bool *has_hinfo, bool *has_sinfo)
{
	struct quic_stream_table *streams;
	struct cmsghdr *cmsg;
	s64 active;

	if (msg->msg_flags & ~QUIC_MSG_FLAGS) /* Reject unsupported flags. */
		return -EINVAL;

	if (quic_is_closed(sk) || quic_is_listen(sk))
		return -EPIPE;

	sinfo->stream_id = -1;
	/* Iterate over control messages and parse QUIC-level metadata. */
	for_each_cmsghdr(cmsg, msg) {
		if (!CMSG_OK(msg, cmsg))
			return -EINVAL;

		if (cmsg->cmsg_level != SOL_QUIC)
			continue;

		switch (cmsg->cmsg_type) {
		case QUIC_HANDSHAKE_INFO:
			quic_copy_common(hinfo, sizeof(*hinfo), CMSG_DATA(cmsg),
					 cmsg->cmsg_len - CMSG_LEN(0));
			*has_hinfo = true;
			break;
		case QUIC_STREAM_INFO:
			quic_copy_common(sinfo, sizeof(*sinfo), CMSG_DATA(cmsg),
					 cmsg->cmsg_len - CMSG_LEN(0));
			if (sinfo->stream_flags & ~QUIC_MSG_STREAM_FLAGS)
				return -EINVAL;
			*has_sinfo = true;
			break;
		default:
			return -EINVAL;
		}
	}

	if (*has_hinfo) /* Handshake metadata present; skip stream handling. */
		return 0;

	if (!*has_sinfo) /* No stream info; inherit flags from msg_flags. */
		sinfo->stream_flags |= (msg->msg_flags & QUIC_MSG_STREAM_FLAGS);

	if (sinfo->stream_id != -1)
		return 0;

	/* No explicit stream; use the most recently opened stream. */
	streams = quic_streams(sk);
	active = streams->send.active_stream_id;
	if (active != -1) {
		sinfo->stream_id = active;
		return 0;
	}
	/* No active stream, pick the next to open based on stream direction. */
	sinfo->stream_id = streams->send.next_bidi_stream_id;
	if (sinfo->stream_flags & MSG_QUIC_STREAM_UNI)
		sinfo->stream_id = streams->send.next_uni_stream_id;
	return 0;
}

/* Returns true if stream_id is within allowed limits or false otherwise.
 * If MSG_QUIC_STREAM_SNDBLOCK is set, may send a STREAMS_BLOCKED frame.
 */
static bool quic_sock_stream_available(struct sock *sk, s64 stream_id,
				       u32 flags)
{
	struct quic_stream_table *streams = quic_streams(sk);
	u8 type, blocked;

	if (!quic_stream_id_exceeds(streams, stream_id, true))
		return true;

	if (!(flags & MSG_QUIC_STREAM_SNDBLOCK))
		return false;

	blocked = streams->send.bidi_blocked;
	type = QUIC_FRAME_STREAMS_BLOCKED_BIDI;
	if (stream_id & QUIC_STREAM_TYPE_UNI_MASK) {
		blocked = streams->send.uni_blocked;
		type = QUIC_FRAME_STREAMS_BLOCKED_UNI;
	}

	if (!blocked)
		quic_outq_transmit_frame(sk, type, &stream_id, 0, false,
					 GFP_KERNEL);
	return false;
}

/* Wait until the given stream ID becomes available for sending. */
static int quic_wait_for_stream(struct sock *sk, s64 stream_id, u32 flags)
{
	long timeo = sock_sndtimeo(sk, flags & MSG_QUIC_STREAM_DONTWAIT);
	DEFINE_WAIT(wait);
	int err = 0;

	for (;;) {
		prepare_to_wait_exclusive(sk_sleep(sk), &wait,
					  TASK_INTERRUPTIBLE);
		if (quic_is_closed(sk)) {
			err = -EPIPE;
			pr_debug("%s: sk closed\n", __func__);
			break;
		}
		if (sk->sk_err) {
			err = -EPIPE;
			pr_debug("%s: sk_err: %d\n", __func__, sk->sk_err);
			break;
		}
		if (signal_pending(current)) {
			err = sock_intr_errno(timeo);
			break;
		}
		if (!timeo) {
			err = -EAGAIN;
			break;
		}
		if (quic_sock_stream_available(sk, stream_id, flags))
			break;

		release_sock(sk);
		timeo = schedule_timeout(timeo);
		lock_sock(sk);
	}
	finish_wait(sk_sleep(sk), &wait);
	return err;
}

/* Get the send stream object for the given stream ID.  May wait if the stream
 * isn't immediately available.
 */
static struct quic_stream *quic_sock_send_stream(struct sock *sk,
						 struct quic_stream_info *sinfo)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_APP);
	struct quic_stream_table *streams = quic_streams(sk);
	bool is_serv = quic_is_serv(sk);
	struct quic_stream *stream;
	gfp_t gfp = GFP_KERNEL;
	int err;

	stream = quic_stream_get(streams, sinfo->stream_id, sinfo->stream_flags,
				 is_serv, true, gfp);
	if (!IS_ERR(stream))
		goto out;
	if (PTR_ERR(stream) != -EAGAIN)
		return stream;

	/* App send keys are not ready yet, likely sending 0-RTT data.  Do not
	 * wait for stream availability if it's beyond the current limit;
	 * return an error immediately instead.
	 */
	if (!crypto->send_ready)
		return ERR_PTR(-EINVAL);

	if (!quic_sock_stream_available(sk, sinfo->stream_id,
					sinfo->stream_flags)) {
		err = quic_wait_for_stream(sk, sinfo->stream_id,
					   sinfo->stream_flags);
		if (err)
			return ERR_PTR(err);
	}

	/* Stream should now be available, retry getting the stream. */
	stream = quic_stream_get(streams, sinfo->stream_id, sinfo->stream_flags,
				 is_serv, true, gfp);
	if (IS_ERR(stream))
		return stream;
out:
	if ((sinfo->stream_flags & MSG_QUIC_STREAM_NEW) &&
	    stream->send.state != QUIC_STREAM_SEND_STATE_READY)
		return ERR_PTR(-EINVAL);
	if (stream->send.state >= QUIC_STREAM_SEND_STATE_SENT)
		return ERR_PTR(-EINVAL); /* Closed/finished stream. */
	return stream;
}

/* Wait until send buffer has enough space for sending. */
static int quic_wait_for_send(struct sock *sk, u32 flags, int len)
{
	long timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);
	DEFINE_WAIT(wait);
	int err = 0;

	for (;;) {
		prepare_to_wait_exclusive(sk_sleep(sk), &wait,
					  TASK_INTERRUPTIBLE);
		if (quic_is_closed(sk)) {
			err = -EPIPE;
			pr_debug("%s: sk closed\n", __func__);
			break;
		}
		if (sk->sk_err) {
			err = -EPIPE;
			pr_debug("%s: sk_err: %d\n", __func__, sk->sk_err);
			break;
		}
		if (signal_pending(current)) {
			err = sock_intr_errno(timeo);
			break;
		}
		if (!timeo) {
			err = -EAGAIN;
			break;
		}
		if (len <= sk_stream_wspace(sk) && sk_wmem_schedule(sk, len))
			break;

		release_sock(sk);
		timeo = schedule_timeout(timeo);
		lock_sock(sk);
	}
	finish_wait(sk_sleep(sk), &wait);
	return err;
}

/* Check if a QUIC stream is writable. */
static bool quic_sock_stream_writable(struct sock *sk,
				      struct quic_stream *stream,
				      u32 flags, int len)
{
	/* Check if flow control limits allow sending 'len' bytes. */
	if (quic_outq_flow_control(sk, stream, len,
				   flags & MSG_QUIC_STREAM_SNDBLOCK))
		return false;
	/* Check socket send buffer space and memory scheduling capacity. */
	if (sk_stream_wspace(sk) < len || !sk_wmem_schedule(sk, len))
		return false;
	return true;
}

/* Wait until a QUIC stream is writable for sending data. */
static int quic_wait_for_stream_send(struct sock *sk,
				     struct quic_stream *stream,
				     u32 flags, int len)
{
	long timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);
	struct quic_stream_table *streams = quic_streams(sk);
	s64 stream_id = stream->id;
	DEFINE_WAIT(wait);
	int err = 0;

	for (;;) {
		prepare_to_wait_exclusive(sk_sleep(sk), &wait,
					  TASK_INTERRUPTIBLE);
		if (quic_is_closed(sk)) {
			err = -EPIPE;
			pr_debug("%s: sk closed\n", __func__);
			break;
		}
		if (sk->sk_err) {
			err = -EPIPE;
			pr_debug("%s: sk_err: %d\n", __func__, sk->sk_err);
			break;
		}
		if (signal_pending(current)) {
			err = sock_intr_errno(timeo);
			break;
		}
		if (!timeo) {
			err = -EAGAIN;
			/* If the stream is blocked due to flow control limits
			 * (not socket buffer), return ENOSPC instead. This
			 * distinction helps applications detect when they
			 * should switch to sending on other streams (e.g., to
			 * implement fair scheduling).
			 */
			if (quic_outq_wspace(sk, stream) < (u64)len)
				err = -ENOSPC;
			break;
		}
		if (quic_sock_stream_writable(sk, stream, flags, len))
			break;

		release_sock(sk);
		timeo = schedule_timeout(timeo);
		lock_sock(sk);

		/* Re-fetch the stream after sleeping. It may have been closed,
		 * reset, or freed while the socket lock was released.
		 */
		stream = quic_stream_find(streams, stream_id);
		if (!stream ||
		    stream->send.state >= QUIC_STREAM_SEND_STATE_SENT) {
			err = -EINVAL;
			break;
		}
	}
	finish_wait(sk_sleep(sk), &wait);
	return err;
}

static int quic_sendmsg(struct sock *sk, struct msghdr *msg, size_t msg_len)
{
	bool delay, has_hinfo = false, has_sinfo = false;
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_handshake_info hinfo = {};
	struct quic_stream_info sinfo = {};
	struct quic_msginfo msginfo = {};
	int err = 0, bytes = 0, len = 1;
	struct quic_crypto *crypto;
	struct quic_stream *stream;
	u32 flags = msg->msg_flags;
	struct quic_frame *frame;
	gfp_t gfp = GFP_KERNEL;
	u8 level;

	lock_sock(sk);
	err = quic_msghdr_parse(sk, msg, &hinfo, &sinfo, &has_hinfo,
				&has_sinfo);
	if (err)
		goto err;

	delay = !!(flags & MSG_MORE); /* Determine if this is a delayed send. */
	if (has_hinfo) { /* Handshake Messages Send Path. */
		/* Initial, Handshake and App (TLS NewSessionTicket) only. */
		if (hinfo.crypto_level >= QUIC_CRYPTO_EARLY) {
			err = -EINVAL;
			goto err;
		}
		crypto = quic_crypto(sk, hinfo.crypto_level);
		if (!crypto->send_ready) {
			/* Cannot send until crypto keys are ready. */
			err = -EINVAL;
			goto err;
		}
		/* Set packet context (overhead, MSS, etc.) before
		 * fragmentation.
		 */
		if (quic_packet_config(sk, hinfo.crypto_level, 0)) {
			err = -ENETUNREACH;
			goto err;
		}
		if (!msg_len) {
			err = -EMSGSIZE;
			goto err;
		}

		/* Prepare the message info used by the frame creator. */
		msginfo.level = hinfo.crypto_level;
		msginfo.msg = &msg->msg_iter;
		/* Send until all data from the message iterator is consumed. */
		while (iov_iter_count(&msg->msg_iter) > 0) {
			if (sk_stream_wspace(sk) < len ||
			    !sk_wmem_schedule(sk, len)) {
				if (outq->force_delay) {
					/* Push buffered data if MSG_MORE was
					 * used.
					 */
					outq->force_delay = 0;
					quic_outq_transmit(sk, gfp);
				}
				err = quic_wait_for_send(sk, flags, len);
				if (err) {
					/* Return error only if nothing sent. */
					if (!bytes)
						goto err;
					goto out;
				}
			}
			frame = quic_frame_create(sk, QUIC_FRAME_CRYPTO,
						  &msginfo, gfp);
			if (IS_ERR(frame)) {
				if (!bytes) {
					/* Return error only if nothing sent. */
					err = PTR_ERR(frame);
					goto err;
				}
				goto out;
			}
			len = frame->bytes;
			if (!sk_wmem_schedule(sk, len)) {
				/* Memory pressure: roll back the iterator and
				 * discard the frame.
				 */
				iov_iter_revert(msginfo.msg, len);
				quic_frame_put(frame);
				/* Retry next frame with len = frame->bytes. */
				continue;
			}
			bytes += frame->bytes;
			/* Pass the delay flag to outqueue. */
			outq->force_delay = delay;
			/* Advance crypto offset. */
			crypto->send_offset += frame->bytes;
			quic_outq_ctrl_tail(sk, frame, delay, gfp);
			len = 1; /* Reset minimal len guess for next frame. */
		}
		goto out;
	}

	level = quic_is_established(sk) ? QUIC_CRYPTO_APP : QUIC_CRYPTO_EARLY;
	if (quic_packet_config(sk, level, 0)) {
		err = -ENETUNREACH;
		goto err;
	}

	if (flags & MSG_QUIC_DATAGRAM) { /* Datagram Messages Send Path. */
		if (!outq->max_datagram_frame_size) {
			/* Peer doesn't allow datagrams. */
			err = -EINVAL;
			goto err;
		}
		if (!msg_len || msg_len > sk->sk_sndbuf) {
			err = -EMSGSIZE;
			goto err;
		}
		len = msg_len;
		if (sk_stream_wspace(sk) < len || !sk_wmem_schedule(sk, len)) {
			if (outq->force_delay) {
				outq->force_delay = 0;
				quic_outq_transmit(sk, gfp);
			}
			err = quic_wait_for_send(sk, flags, len);
			if (err)
				goto err;
		}
		/* Only Datagram frames with a length field are supported. */
		frame = quic_frame_create(sk, QUIC_FRAME_DATAGRAM_LEN,
					  &msg->msg_iter, gfp);
		if (IS_ERR(frame)) {
			err = PTR_ERR(frame);
			goto err;
		}
		bytes += frame->bytes;
		outq->force_delay = delay;
		quic_outq_dgram_tail(sk, frame, delay);
		goto out;
	}

	/* Stream Messages Send Path. */
	stream = quic_sock_send_stream(sk, &sinfo);
	if (IS_ERR(stream)) {
		err = PTR_ERR(stream);
		goto err;
	}

	/* Logic is similar to handshake messages send path. */
	msginfo.stream = stream;
	msginfo.msg = &msg->msg_iter;
	msginfo.flags = sinfo.stream_flags;
	flags |= sinfo.stream_flags;

	if (!msg_len) { /* Allow stream FIN without data. */
		if (!(flags & MSG_QUIC_STREAM_FIN)) {
			err = -EMSGSIZE;
			goto err;
		}
		len = 0;
	}

	do {
		if (!quic_sock_stream_writable(sk, stream, flags, len)) {
			if (outq->force_delay) {
				outq->force_delay = 0;
				quic_outq_transmit(sk, gfp);
			}
			err = quic_wait_for_stream_send(sk, stream, flags, len);
			if (err) {
				/* Return -ENOSPC (flow control limit hit) only
				 * if stream info cmsg was set; otherwise treat
				 * it as -EAGAIN.
				 */
				if (err == -ENOSPC && !has_sinfo)
					err = -EAGAIN;
				if (!bytes)
					goto err;
				goto out;
			}
		}

		/* Probe appendable size. */
		len = quic_outq_stream_append(sk, &msginfo, false);
		if (len >= 0) {
			if (!sk_wmem_schedule(sk, len))
				continue; /* Retry on memory pressure. */
			len = quic_outq_stream_append(sk, &msginfo, true);
			if (len >= 0) { /* Appended. */
				bytes += len;
				 /* Reset minimal len guess for next frame. */
				len = 1;
				continue;
			}
		}

		frame = quic_frame_create(sk, QUIC_FRAME_STREAM, &msginfo, gfp);
		if (IS_ERR(frame)) {
			if (!bytes) {
				err = PTR_ERR(frame);
				goto err;
			}
			goto out;
		}
		len = frame->bytes;
		if (!sk_wmem_schedule(sk, len)) {
			iov_iter_revert(msginfo.msg, len);
			quic_frame_put(frame);
			continue;
		}
		bytes += frame->bytes;
		outq->force_delay = delay;
		quic_outq_stream_tail(sk, frame, delay);
		len = 1;
		/* Allow FIN-only frame by checking iov_iter_count() after send
		 * with do-while.
		 */
	} while (iov_iter_count(msginfo.msg) > 0);
out:
	err = bytes; /* Return total bytes sent. */
err:
	/* Handle error and possibly send SIGPIPE. */
	if (err < 0 && !has_hinfo && !(flags & MSG_QUIC_DATAGRAM))
		err = sk_stream_error(sk, flags, err);
	release_sock(sk);
	return err;
}

/* Wait for an incoming QUIC packet. */
static int quic_wait_for_packet(struct sock *sk, struct list_head *head,
				u32 flags)
{
	long timeo = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);
	DEFINE_WAIT(wait);
	int err = 0;

	if (quic_is_listen(sk))
		return -ENOTCONN;

	for (;;) {
		if (!list_empty(head))
			break;
		prepare_to_wait_exclusive(sk_sleep(sk), &wait,
					  TASK_INTERRUPTIBLE);
		if (quic_is_closed(sk)) {
			err = -ENOTCONN;
			pr_debug("%s: sk closed\n", __func__);
			break;
		}
		if (sk->sk_err) {
			err = -ENOTCONN;
			pr_debug("%s: sk_err: %d\n", __func__, sk->sk_err);
			break;
		}
		if (signal_pending(current)) {
			err = sock_intr_errno(timeo);
			break;
		}
		if (!timeo) {
			err = -EAGAIN;
			break;
		}

		release_sock(sk);
		timeo = schedule_timeout(timeo);
		lock_sock(sk);
	}
	finish_wait(sk_sleep(sk), &wait);
	return err;
}

static int quic_recvmsg(struct sock *sk, struct msghdr *msg, size_t msg_len,
			int flags)
{
	u32 copy, copied = 0, freed = 0, bytes = 0;
	struct quic_handshake_info hinfo = {};
	struct quic_stream_info sinfo = {};
	struct quic_stream *stream = NULL;
	struct quic_frame *frame, *next;
	struct list_head *head;
	s64 stream_id = -1;
	int err, fin;

	lock_sock(sk);

	head = &quic_inq(sk)->recv_list;

	err = quic_wait_for_packet(sk, head, flags);
	if (err)
		goto out;

	/* Iterate over each received frame in the list. */
	list_for_each_entry_safe(frame, next, head, list) {
		/* Determine how much data to copy: the minimum of the
		 * remaining data in the frame and the remaining user buffer
		 * space.
		 */
		copy = min_t(u32, frame->bytes - frame->read_offset,
			     msg_len - copied);
		if (copy) { /* Copy data from frame to user message iterator. */
			copy = copy_to_iter(frame->data + frame->read_offset,
					    copy, &msg->msg_iter);
			if (!copy) {
				if (!copied) {
					/* Return err only if nothing copied. */
					err = -EFAULT;
					goto out;
				}
				break;
			}
			copied += copy; /* Accumulate total copied bytes. */
		}
		fin = frame->stream_fin;
		stream = frame->stream;
		stream_id = frame->stream_id;
		if (frame->event) { /* An Event received. */
			msg->msg_flags |= MSG_QUIC_NOTIFICATION;
		} else if (frame->level) {
			/* Attach handshake info if crypto level present. */
			hinfo.crypto_level = frame->level;
			put_cmsg(msg, SOL_QUIC, QUIC_HANDSHAKE_INFO,
				 sizeof(hinfo), &hinfo);
		} else if (frame->dgram) { /* A Datagram Message received. */
			msg->msg_flags |= MSG_QUIC_DATAGRAM;
		}
		if (copy != frame->bytes - frame->read_offset) {
			/* Partial copy: update read_offset and exit loop. */
			if (!(flags & MSG_PEEK))
				frame->read_offset += copy;
			break;
		}
		if (!(flags & MSG_PEEK)) {
			if (stream_id != -1) /* Stream frame. */
				freed += frame->bytes;

			bytes += quic_frame_size(frame);
			list_del(&frame->list);
			quic_frame_put(frame);
		}
		if (stream_id == -1) { /* Non-stream frame. */
			msg->msg_flags |= MSG_EOR;
			break;
		}
		if (fin) {
			sinfo.stream_flags |= MSG_QUIC_STREAM_FIN;
			break;
		}

		/* Stop if next frame is not part of this stream or no more
		 * data to copy.
		 */
		if (list_entry_is_head(next, head, list) || copied >= msg_len)
			break;
		if (next->stream_id == -1 || next->stream_id != stream_id)
			break;
	}

	if (stream_id != -1) {
		/* Attach stream info if stream data was processed. */
		sinfo.stream_id = stream_id;
		put_cmsg(msg, SOL_QUIC, QUIC_STREAM_INFO, sizeof(sinfo),
			 &sinfo);
		if (msg->msg_flags & MSG_CTRUNC)
			msg->msg_flags |= sinfo.stream_flags;

		/* Update flow control accounting for freed bytes. */
		quic_inq_flow_control(sk, stream, freed, GFP_KERNEL);
	}

	quic_inq_data_rfree(bytes, sk); /* Release receive memory accounting. */
	err = (int)copied;
out:
	release_sock(sk);
	return err;
}

/* Wait until a new connection request is available on the listen socket. */
static int quic_wait_for_accept(struct sock *sk, u32 flags)
{
	long timeo = sock_rcvtimeo(sk, flags & O_NONBLOCK);
	struct list_head *head = quic_reqs(sk);
	DEFINE_WAIT(wait);
	int err = 0;

	for (;;) {
		if (!list_empty(head))
			break;
		prepare_to_wait_exclusive(sk_sleep(sk), &wait,
					  TASK_INTERRUPTIBLE);
		if (!quic_is_listen(sk)) {
			err = -EINVAL;
			pr_debug("%s: sk not listening\n", __func__);
			break;
		}
		if (sk->sk_err) {
			err = -EINVAL;
			pr_debug("%s: sk_err: %d\n", __func__, sk->sk_err);
			break;
		}
		if (signal_pending(current)) {
			err = sock_intr_errno(timeo);
			break;
		}
		if (!timeo) {
			err = -EAGAIN;
			break;
		}

		release_sock(sk);
		timeo = schedule_timeout(timeo);
		lock_sock(sk);
	}
	finish_wait(sk_sleep(sk), &wait);
	return err;
}

static void quic_sock_fetch_config(struct sock *sk, struct quic_config *config)
{
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_cong *cong = quic_cong(sk);

	config->receive_session_ticket = outq->receive_session_ticket;
	config->validate_peer_address = outq->validate_peer_address;
	config->certificate_request = outq->certificate_request;
	config->stream_data_nodelay = outq->stream_data_nodelay;
	config->payload_cipher_type = outq->payload_cipher_type;
	config->version = outq->version;

	config->initial_smoothed_rtt = cong->initial_srtt;
	config->congestion_control_algo = cong->algo;

	config->plpmtud_probe_interval = paths->plpmtud_interval;
	config->keepalive_probe_interval = paths->keepalive_interval;
}

/* Apply QUIC configuration settings to a socket. */
static void quic_sock_apply_config(struct sock *sk, struct quic_config *config)
{
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_outqueue *outq = quic_outq(sk);
	struct quic_cong *cong = quic_cong(sk);

	outq->receive_session_ticket = config->receive_session_ticket;
	outq->validate_peer_address = !!config->validate_peer_address;
	outq->certificate_request = config->certificate_request;
	outq->stream_data_nodelay = !!config->stream_data_nodelay;
	outq->payload_cipher_type = config->payload_cipher_type;
	outq->version = config->version;

	quic_cong_set_srtt(cong, config->initial_smoothed_rtt);
	quic_cong_set_algo(cong, config->congestion_control_algo);

	paths->plpmtud_interval = config->plpmtud_probe_interval;
	paths->keepalive_interval = config->keepalive_probe_interval;
}

/* Initialize an accept QUIC socket from a listen socket. */
static int quic_accept_sock_init(struct sock *nsk, struct sock *sk)
{
	struct quic_data *alpn = quic_alpn(sk);
	struct quic_transport_param param = {};
	struct quic_config config = {};
	int err;

	inet_sk(nsk)->inet_opt = NULL;
	if (sk->sk_family == AF_INET6) /* Set IPv6 state if applicable. */
		inet_sk(nsk)->pinet6 = &((struct quic6_sock *)nsk)->inet6;

	err = quic_init_sock(nsk);
	if (err)
		return err;

	/* Duplicate ALPN from listen to accept socket for handshake. */
	if (quic_data_dup(quic_alpn(nsk), alpn->data, alpn->len, GFP_KERNEL))
		return -ENOMEM;

	memcpy(quic_crypto(nsk, QUIC_CRYPTO_INITIAL)->tx_secret[1],
	       quic_crypto(sk, QUIC_CRYPTO_INITIAL)->tx_secret[1],
	       QUIC_SECRET_LEN);

	quic_inq(nsk)->events = quic_inq(sk)->events;

	/* Copy the QUIC settings and transport parameters to accept socket. */
	quic_sock_fetch_config(sk, &config);
	quic_sock_apply_config(nsk, &config);
	quic_sock_fetch_transport_param(sk, &param);
	quic_sock_apply_transport_param(nsk, &param);

	return 0;
}

/* Finalize setup for an accept QUIC socket. */
static int quic_accept_sock_setup(struct sock *sk,
				  struct quic_request_sock *req)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_packet *packet = quic_packet(sk);
	struct quic_inqueue *inq = quic_inq(sk);
	struct quic_conn_id conn_id = {};
	gfp_t gfp = GFP_KERNEL;
	struct sk_buff *skb;
	int err;

	quic_path_set_saddr(paths, 0, &req->saddr);
	err = quic_path_bind(sk, paths, 0);
	if (err)
		return err;
	quic_set_sk_addr(sk, &req->saddr, true);

	lock_sock_nested(sk, SINGLE_DEPTH_NESTING);
	/* Set destination address and resolve route (may also auto-set source
	 * address).
	 */
	quic_path_set_daddr(paths, 0, &req->daddr);
	err = quic_packet_route(sk);
	if (err)
		goto out;
	quic_set_sk_addr(sk, &req->daddr, false);

	/* Generate and add destination and source connection IDs. */
	quic_conn_id_generate(&conn_id);
	err = quic_conn_id_add(quic_source(sk), &conn_id, 0, sk, gfp);
	if (err)
		goto out;
	err = quic_conn_id_add(quic_dest(sk), &req->scid, 0, NULL, gfp);
	if (err)
		goto out;

	/* Install initial encryption keys for handshake. */
	err = quic_crypto_set_cipher(crypto, TLS_CIPHER_AES_GCM_128);
	if (err)
		goto out;
	err = quic_crypto_initial_keys_install(crypto, &req->dcid, req->version,
					       true);
	if (err)
		goto out;
	err = quic_crypto_set_token_secret(crypto);
	if (err)
		goto out;
	/* Record the QUIC version offered by the peer. May later change if
	 * Compatible Version Negotiation is triggered.
	 */
	packet->version = req->version;

	/* Save original DCID and retry DCID for building transport parameters,
	 * and identifying the connection in quic_sock_lookup().
	 */
	paths->orig_dcid = req->orig_dcid;
	if (req->retry) {
		paths->retry = 1;
		paths->retry_dcid = req->dcid;
	}

	/* Add socket to hash table, change state to ESTABLISHING, and start
	 * idle timer.
	 */
	quic_set_state(sk, QUIC_SS_ESTABLISHING);
	err = sk->sk_prot->hash(sk);
	if (err)
		goto out;
	quic_timer_start(sk, QUIC_TIMER_IDLE, inq->timeout);
	quic_timer_start(sk, QUIC_TIMER_PATH, paths->keepalive_interval);

	/* Process all packets in backlog list of this socket. */
	while ((skb = __skb_dequeue(&req->backlog_list)) != NULL)
		quic_packet_process(sk, skb, gfp);

out:
	release_sock(sk);
	return err;
}

static struct sock *quic_accept(struct sock *sk, struct proto_accept_arg *arg)
{
	struct quic_request_sock *req;
	struct sock *nsk = NULL;
	int err = -EINVAL;

	lock_sock(sk);

	if (!quic_is_listen(sk))
		goto out;

	err = quic_wait_for_accept(sk, arg->flags);
	if (err)
		goto out;

	nsk = sk_clone(sk, GFP_KERNEL, false);
	if (!nsk) {
		err = -ENOMEM;
		goto out;
	}

	/* Clear all QUIC-specific fields that come after struct inet_sock.
	 * These fields will be explicitly initialized later below.
	 */
	memset((void *)nsk + sizeof(struct inet_sock), 0,
	       nsk->sk_prot->obj_size - sizeof(struct inet_sock));

	/* sk_clone() increments sockets_allocated. quic_init_sock() will
	 * account it again, so undo the extra increment.
	 */
	sk_sockets_allocated_dec(nsk);
	sock_put(nsk); /* sk_clone() increments refcnt to 2; drop the extra. */

	req = list_first_entry(quic_reqs(sk), struct quic_request_sock, list);

	err = quic_accept_sock_init(nsk, sk);
	if (err)
		goto free;

	err = quic_accept_sock_setup(nsk, req);
	if (err) {
		quic_request_sock_free(sk, req);
		goto free;
	}

	/* Record the creation time of this accept socket in microseconds.
	 * Used by quic_accept_sock_exists() to determine if a packet from
	 * sk_backlog of listen socket predates this socket.
	 */
	quic_pnspace(sk, QUIC_CRYPTO_INITIAL)->time = quic_ktime_get_us();
	quic_request_sock_free(sk, req);
out:
	release_sock(sk);
	arg->err = err;
	return nsk;
free:
	quic_set_state(nsk, QUIC_SS_CLOSED);
	sk_common_release(nsk);
	nsk = NULL;
	goto out;
}

static void quic_close(struct sock *sk, long timeout)
{
	lock_sock(sk);

	quic_outq_transmit_app_close(sk);
	sk->sk_prot->unhash(sk);
	quic_set_state(sk, QUIC_SS_CLOSED);

	release_sock(sk);

	sk_common_release(sk);
}

/**
 * quic_do_setsockopt - set a QUIC socket option
 * @sk: socket to configure
 * @optname: option name (QUIC-level)
 * @optval: user buffer containing the option value
 * @optlen: size of the option value
 *
 * Sets a QUIC socket option on a given socket.
 *
 * Return:
 * - On success, 0 is returned.
 * - On error, a negative error value is returned.
 */
int quic_do_setsockopt(struct sock *sk, int optname, sockptr_t optval,
		       unsigned int optlen)
{
	return -EOPNOTSUPP;
}
EXPORT_SYMBOL_GPL(quic_do_setsockopt);

static int quic_setsockopt(struct sock *sk, int level, int optname,
			   sockptr_t optval, unsigned int optlen)
{
	if (level != SOL_QUIC)
		return quic_common_setsockopt(sk, level, optname, optval,
					      optlen);

	return quic_do_setsockopt(sk, optname, optval, optlen);
}

/**
 * quic_do_getsockopt - get a QUIC socket option
 * @sk: socket to query
 * @optname: option name (QUIC-level)
 * @optval: user buffer to receive the option value
 * @optlen: pointer to buffer size; updated with actual size on return
 *
 * Gets a QUIC socket option from a given socket.
 *
 * Return:
 * - On success, 0 is returned.
 * - On error, a negative error value is returned.
 */
int quic_do_getsockopt(struct sock *sk, int optname, sockptr_t optval,
		       sockptr_t optlen)
{
	return -EOPNOTSUPP;
}
EXPORT_SYMBOL_GPL(quic_do_getsockopt);

static int quic_getsockopt(struct sock *sk, int level, int optname,
			   char __user *optval, int __user *optlen)
{
	if (level != SOL_QUIC)
		return quic_common_getsockopt(sk, level, optname, optval,
					      optlen);

	return quic_do_getsockopt(sk, optname, USER_SOCKPTR(optval),
				  USER_SOCKPTR(optlen));
}

static void quic_release_cb(struct sock *sk)
{
	/* Similar to tcp_release_cb(). */
	unsigned long nflags, flags = smp_load_acquire(&sk->sk_tsq_flags);

	do {
		if (!(flags & QUIC_DEFERRED_ALL))
			return;
		nflags = flags & ~QUIC_DEFERRED_ALL;
	} while (!try_cmpxchg(&sk->sk_tsq_flags, &flags, nflags));

	if (flags & QUIC_F_MTU_REDUCED_DEFERRED) {
		quic_packet_rcv_err_pmtu(sk);
		__sock_put(sk);
	}
	if (flags & QUIC_F_LOSS_DEFERRED) {
		quic_timer_loss_handler(sk);
		__sock_put(sk);
	}
	if (flags & QUIC_F_SACK_DEFERRED) {
		quic_timer_sack_handler(sk);
		__sock_put(sk);
	}
	if (flags & QUIC_F_PATH_DEFERRED) {
		quic_timer_path_handler(sk);
		__sock_put(sk);
	}
	if (flags & QUIC_F_PMTU_DEFERRED) {
		quic_timer_pmtu_handler(sk);
		__sock_put(sk);
	}
	if (flags & QUIC_F_PACE_DEFERRED) {
		quic_timer_pace_handler(sk);
		__sock_put(sk);
	}
	if (flags & QUIC_F_TXQ_DEFERRED) {
		quic_packet_flush_txq(sk);
		__sock_put(sk);
	}
	if (flags & QUIC_F_RXQ_DEFERRED) {
		quic_packet_flush_rxq(sk);
		__sock_put(sk);
	}
}

static int quic_disconnect(struct sock *sk, int flags)
{
	return -EOPNOTSUPP;
}

static void quic_shutdown(struct sock *sk, int how)
{
	if (!(how & SEND_SHUTDOWN))
		goto out;

	quic_outq_transmit_app_close(sk);
out:
	quic_set_state(sk, QUIC_SS_CLOSED);
}

static int quic_backlog_rcv(struct sock *sk, struct sk_buff *skb)
{
	return quic_packet_process(sk, skb, GFP_ATOMIC);
}

struct proto quic_prot = {
	.name		=  "QUIC",
	.owner		=  THIS_MODULE,
	.init		=  quic_init_sock,
	.destroy	=  quic_destroy_sock,
	.shutdown	=  quic_shutdown,
	.setsockopt	=  quic_setsockopt,
	.getsockopt	=  quic_getsockopt,
	.connect	=  quic_connect,
	.bind		=  quic_bind,
	.close		=  quic_close,
	.disconnect	=  quic_disconnect,
	.sendmsg	=  quic_sendmsg,
	.recvmsg	=  quic_recvmsg,
	.accept		=  quic_accept,
	.hash		=  quic_hash,
	.unhash		=  quic_unhash,
	.backlog_rcv	=  quic_backlog_rcv,
	.release_cb	=  quic_release_cb,
	.no_autobind	=  true,
	.obj_size	=  sizeof(struct quic_sock),
	.sysctl_mem		=  sysctl_quic_mem,
	.sysctl_rmem		=  sysctl_quic_rmem,
	.sysctl_wmem		=  sysctl_quic_wmem,
	.memory_pressure	=  &quic_memory_pressure,
	.enter_memory_pressure	=  quic_enter_memory_pressure,
	.memory_allocated	=  &quic_memory_allocated,
	.per_cpu_fw_alloc	=  &quic_memory_per_cpu_fw_alloc,
	.sockets_allocated	=  &quic_sockets_allocated,
};

struct proto quicv6_prot = {
	.name		=  "QUICv6",
	.owner		=  THIS_MODULE,
	.init		=  quic_init_sock,
	.destroy	=  quic_destroy_sock,
	.shutdown	=  quic_shutdown,
	.setsockopt	=  quic_setsockopt,
	.getsockopt	=  quic_getsockopt,
	.connect	=  quic_connect,
	.bind		=  quic_bind,
	.close		=  quic_close,
	.disconnect	=  quic_disconnect,
	.sendmsg	=  quic_sendmsg,
	.recvmsg	=  quic_recvmsg,
	.accept		=  quic_accept,
	.hash		=  quic_hash,
	.unhash		=  quic_unhash,
	.backlog_rcv	=  quic_backlog_rcv,
	.release_cb	=  quic_release_cb,
	.no_autobind	=  true,
	.obj_size	= sizeof(struct quic6_sock),
	.ipv6_pinfo_offset	=  offsetof(struct quic6_sock, inet6),
	.sysctl_mem		=  sysctl_quic_mem,
	.sysctl_rmem		=  sysctl_quic_rmem,
	.sysctl_wmem		=  sysctl_quic_wmem,
	.memory_pressure	=  &quic_memory_pressure,
	.enter_memory_pressure	=  quic_enter_memory_pressure,
	.memory_allocated	=  &quic_memory_allocated,
	.per_cpu_fw_alloc	=  &quic_memory_per_cpu_fw_alloc,
	.sockets_allocated	=  &quic_sockets_allocated,
};
