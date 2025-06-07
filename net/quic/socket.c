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
#include <linux/version.h>
#include <net/tls.h>

#include "socket.h"

static DEFINE_PER_CPU(int, quic_memory_per_cpu_fw_alloc);
static unsigned long quic_memory_pressure;
static atomic_long_t quic_memory_allocated;

static void quic_enter_memory_pressure(struct sock *sk)
{
	WRITE_ONCE(quic_memory_pressure, 1);
}

/* Check if a matching request sock already exists.  Match is based on source/destination
 * addresses and DCID.
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
struct quic_request_sock *quic_request_sock_enqueue(struct sock *sk, struct quic_conn_id *odcid,
						    u8 retry)
{
	struct quic_packet *packet = quic_packet(sk);
	struct quic_request_sock *req;

	if (sk_acceptq_is_full(sk)) /* Refuse new request if the accept queue is full. */
		return NULL;

	req = kzalloc(sizeof(*req), GFP_ATOMIC);
	if (!req)
		return NULL;

	req->version = packet->version;
	req->daddr = packet->daddr;
	req->saddr = packet->saddr;
	req->scid = packet->scid;
	req->dcid = packet->dcid;
	req->orig_dcid = *odcid;
	req->retry = retry;

	skb_queue_head_init(&req->backlog_list);

	/* Enqueue request into the listen socket’s pending list for accept(). */
	list_add_tail(&req->list, quic_reqs(sk));
	sk_acceptq_added(sk);
	return req;
}

static struct quic_request_sock *quic_request_sock_dequeue(struct sock *sk)
{
	struct quic_request_sock *req;

	req = list_first_entry(quic_reqs(sk), struct quic_request_sock, list);

	list_del_init(&req->list);
	sk_acceptq_removed(sk);
	return req;
}

int quic_request_sock_backlog_tail(struct sock *sk, struct quic_request_sock *req,
				   struct sk_buff *skb)
{
	/* Use listen sock sk_rcvbuf to limit the request sock's backlog len. */
	if (req->blen + skb->len > sk->sk_rcvbuf)
		return -ENOMEM;

	__skb_queue_tail(&req->backlog_list, skb);
	req->blen += skb->len;
	sk->sk_data_ready(sk);
	return 0;
}

static void quic_request_sock_free(struct quic_request_sock *req)
{
	__skb_queue_purge(&req->backlog_list);
	kfree(req);
}

/* Check if a matching accept socket exists.  This is needed because an accept socket
 * might have been created after this packet was enqueued in the listen socket's backlog.
 */
bool quic_accept_sock_exists(struct sock *sk, struct sk_buff *skb)
{
	struct quic_pnspace *space = quic_pnspace(sk, QUIC_CRYPTO_INITIAL);
	struct quic_packet *packet = quic_packet(sk);
	bool exist = false;

	/* Skip if packet is newer than the last accept socket creation time.  No matching
	 * socket could exist in this case.
	 */
	if (QUIC_SKB_CB(skb)->time > space->time)
		return exist;

	/* Look up an accepted socket that matches the packet's addresses and DCID. */
	local_bh_disable();
	sk = quic_sock_lookup(skb, &packet->saddr, &packet->daddr, &packet->dcid);
	if (!sk)
		goto out;

	/* Found a matching accept socket. Process the packet with this socket. */
	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		/* Socket is busy (owned by user context): queue to backlog. */
		if (sk_add_backlog(sk, skb, READ_ONCE(sk->sk_rcvbuf)))
			kfree_skb(skb);
	} else {
		/* Socket not busy: process immediately. */
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
 * This function searches the established (non-listening) QUIC socket table for a socket that
 * matches the source and dest addresses and, optionally, the dest connection ID (DCID). The
 * value returned by quic_path_orig_dcid() might be the original dest connection ID from the
 * ClientHello or the Source Connection ID from a Retry packet before.
 *
 * The DCID is provided from a handshake packet when searching by source connection ID fails,
 * such as when the peer has not yet received server's response and updated the DCID.
 *
 * Return: A pointer to the matching connected socket, or NULL if no match is found.
 */
struct sock *quic_sock_lookup(struct sk_buff *skb, union quic_addr *sa, union quic_addr *da,
			      struct quic_conn_id *dcid)
{
	struct net *net = dev_net(skb->dev);
	struct quic_path_group *paths;
	struct quic_hash_head *head;
	struct sock *sk;

	head = quic_sock_head(net, sa, da);
	spin_lock(&head->s_lock);
	sk_for_each(sk, &head->head) {
		if (net != sock_net(sk))
			continue;
		paths = quic_paths(sk);
		if (quic_cmp_sk_addr(sk, quic_path_saddr(paths, 0), sa) &&
		    quic_cmp_sk_addr(sk, quic_path_daddr(paths, 0), da) &&
		    quic_path_usock(paths, 0) == skb->sk &&
		    (!dcid || !quic_conn_id_cmp(quic_path_orig_dcid(paths), dcid))) {
			sock_hold(sk);
			break;
		}
	}
	spin_unlock(&head->s_lock);

	return sk;
}

/* Find the listening QUIC socket for an incoming packet.
 *
 * This function searches the QUIC socket table for a listening socket that matches the dest
 * address and port, and the ALPN(s) if presented in the ClientHello.  If multiple listening
 * sockets are bound to the same address, port, and ALPN(s) (e.g., via SO_REUSEPORT), this
 * function selects a socket from the reuseport group.
 *
 * Return: A pointer to the matching listening socket, or NULL if no match is found.
 */
struct sock *quic_listen_sock_lookup(struct sk_buff *skb, union quic_addr *sa, union quic_addr *da,
				     struct quic_data *alpns)
{
	struct net *net = dev_net(skb->dev);
	struct sock *sk = NULL, *tmp;
	struct quic_hash_head *head;
	struct quic_data alpn;
	union quic_addr *a;
	u64 length;
	u32 len;
	u8 *p;

	head = quic_listen_sock_head(net, ntohs(sa->v4.sin_port));
	spin_lock(&head->s_lock);

	if (!alpns->len) { /* No ALPN entries present or failed to parse the ALPNs. */
		sk_for_each(tmp, &head->head) {
			/* If alpns->data != NULL, TLS parsing succeeded but no ALPN was found.
			 * In this case, only match sockets that have no ALPN set.
			 */
			a = quic_path_saddr(quic_paths(tmp), 0);
			if (net == sock_net(tmp) && quic_cmp_sk_addr(tmp, a, sa) &&
			    quic_path_usock(quic_paths(tmp), 0) == skb->sk &&
			    (!alpns->data || !quic_alpn(tmp)->len)) {
				sk = tmp;
				if (!quic_is_any_addr(a)) /* Prefer specific address match. */
					break;
			}
		}
		goto unlock;
	}

	/* ALPN present: loop through each ALPN entry. */
	for (p = alpns->data, len = alpns->len; len; len -= length, p += length) {
		quic_get_int(&p, &len, &length, 1);
		quic_data(&alpn, p, length);
		sk_for_each(tmp, &head->head) {
			a = quic_path_saddr(quic_paths(tmp), 0);
			if (net == sock_net(tmp) && quic_cmp_sk_addr(tmp, a, sa) &&
			    quic_path_usock(quic_paths(tmp), 0) == skb->sk &&
			    quic_data_has(quic_alpn(tmp), &alpn)) {
				sk = tmp;
				if (!quic_is_any_addr(a))
					break;
			}
		}
		if (sk)
			break;
	}
unlock:
	if (sk && sk->sk_reuseport)
		sk = reuseport_select_sock(sk, quic_shash(net, da), skb, 1);
	if (sk)
		sock_hold(sk);

	spin_unlock(&head->s_lock);
	return sk;
}

static void quic_write_space(struct sock *sk)
{
	struct socket_wq *wq;

	rcu_read_lock();
	wq = rcu_dereference(sk->sk_wq);
	if (skwq_has_sleeper(wq))
		wake_up_interruptible_sync_poll(&wq->wait, EPOLLOUT | EPOLLWRNORM | EPOLLWRBAND);
	rcu_read_unlock();
}

/* Apply QUIC transport parameters to subcomponents of the socket. */
static void quic_sock_apply_transport_param(struct sock *sk, struct quic_transport_param *p)
{
	struct quic_conn_id_set *id_set = p->remote ? quic_source(sk) : quic_dest(sk);

	quic_inq_set_param(sk, p);
	quic_outq_set_param(sk, p);
	quic_conn_id_set_param(id_set, p);
	quic_path_set_param(quic_paths(sk), p);
	quic_stream_set_param(quic_streams(sk), p, quic_is_serv(sk));
}

/* Fetch QUIC transport parameters from subcomponents of the socket. */
static void quic_sock_fetch_transport_param(struct sock *sk, struct quic_transport_param *p)
{
	struct quic_conn_id_set *id_set = p->remote ? quic_source(sk) : quic_dest(sk);

	quic_inq_get_param(sk, p);
	quic_outq_get_param(sk, p);
	quic_conn_id_get_param(id_set, p);
	quic_path_get_param(quic_paths(sk), p);
	quic_stream_get_param(quic_streams(sk), p, quic_is_serv(sk));
}

static int quic_init_sock(struct sock *sk)
{
	struct quic_transport_param *p = &quic_default_param;
	u8 i;

	sk->sk_destruct = inet_sock_destruct;
	sk->sk_write_space = quic_write_space;
	sock_set_flag(sk, SOCK_USE_WRITE_QUEUE);

	quic_conn_id_set_init(quic_source(sk), 1);
	quic_conn_id_set_init(quic_dest(sk), 0);
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

	WRITE_ONCE(sk->sk_sndbuf, READ_ONCE(sysctl_quic_wmem[1]));
	WRITE_ONCE(sk->sk_rcvbuf, READ_ONCE(sysctl_quic_rmem[1]));

	local_bh_disable();
	sk_sockets_allocated_inc(sk);
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);
	local_bh_enable();

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
	for (i = 0; i < QUIC_CRYPTO_MAX; i++)
		quic_crypto_free(quic_crypto(sk, i));

	quic_path_free(sk, quic_paths(sk), 0);
	quic_path_free(sk, quic_paths(sk), 1);

	quic_conn_id_set_free(quic_source(sk));
	quic_conn_id_set_free(quic_dest(sk));

	quic_stream_free(quic_streams(sk));

	quic_data_free(quic_ticket(sk));
	quic_data_free(quic_token(sk));
	quic_data_free(quic_alpn(sk));

	local_bh_disable();
	sk_sockets_allocated_dec(sk);
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);
	local_bh_enable();
}

static int quic_bind(struct sock *sk, struct sockaddr *addr, int addr_len)
{
	struct quic_path_group *paths = quic_paths(sk);
	union quic_addr a;
	int err = -EINVAL;

	lock_sock_nested(sk, SINGLE_DEPTH_NESTING);

	if (quic_path_saddr(paths, 0)->v4.sin_port || quic_get_user_addr(sk, &a, addr, addr_len))
		goto out;

	quic_path_set_saddr(paths, 0, &a);
	err = quic_path_bind(sk, paths, 0);
	if (err) {
		memset(quic_path_saddr(paths, 0), 0, sizeof(a));
		goto out;
	}
	quic_set_sk_addr(sk, &a, true);

out:
	release_sock(sk);
	return err;
}

static int quic_connect(struct sock *sk, struct sockaddr *addr, int addr_len)
{
	struct quic_conn_id_set *dest = quic_dest(sk), *source = quic_source(sk);
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_packet *packet = quic_packet(sk);
	struct quic_inqueue *inq = quic_inq(sk);
	struct quic_conn_id conn_id, *active;
	union quic_addr *sa, a;
	int err = -EINVAL;

	lock_sock(sk);
	if (!sk_unhashed(sk) || quic_get_user_addr(sk, &a, addr, addr_len))
		goto out;

	/* Set destination address and resolve route (may also auto-set source address). */
	quic_path_set_daddr(paths, 0, &a);
	err = quic_packet_route(sk);
	if (err < 0)
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
	err = quic_conn_id_add(dest, &conn_id, 0, NULL);
	if (err)
		goto out;
	/* Save original DCID for validating server's transport parameters. */
	paths->orig_dcid = conn_id;
	quic_conn_id_generate(&conn_id);
	err = quic_conn_id_add(source, &conn_id, 0, sk);
	if (err)
		goto free;
	active = quic_conn_id_active(dest);

	/* Install initial encryption keys for handshake. */
	err = quic_crypto_set_cipher(crypto, TLS_CIPHER_AES_GCM_128, 0);
	if (err)
		goto free;
	err = quic_crypto_initial_keys_install(crypto, active, packet->version, 0);
	if (err)
		goto free;

	/* Add socket to hash table, change state to ESTABLISHING, and start idle timer. */
	err = sk->sk_prot->hash(sk);
	if (err)
		goto free;
	quic_set_state(sk, QUIC_SS_ESTABLISHING);
	quic_timer_start(sk, QUIC_TIMER_IDLE, inq->timeout);
out:
	release_sock(sk);
	return err;
free:
	quic_conn_id_set_free(source);
	quic_conn_id_set_free(dest);
	quic_crypto_free(crypto);
	goto out;
}

static int quic_hash(struct sock *sk)
{
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_data *alpns = quic_alpn(sk);
	struct net *net = sock_net(sk);
	struct quic_hash_head *head;
	union quic_addr *sa, *da;
	struct sock *nsk;
	int err = 0, any;

	sa = quic_path_saddr(paths, 0);
	da = quic_path_daddr(paths, 0);
	if (!sk->sk_max_ack_backlog) { /* Hash a regular socket with source and dest addrs/ports. */
		head = quic_sock_head(net, sa, da);
		spin_lock_bh(&head->s_lock);
		__sk_add_node(sk, &head->head);
		spin_unlock_bh(&head->s_lock);
		return 0;
	}

	/* Hash a listen socket with source port only. */
	head = quic_listen_sock_head(net, ntohs(sa->v4.sin_port));
	spin_lock_bh(&head->s_lock);

	any = quic_is_any_addr(sa);
	sk_for_each(nsk, &head->head) {
		if (net == sock_net(nsk) && quic_cmp_sk_addr(nsk, quic_path_saddr(paths, 0), sa) &&
		    quic_path_usock(paths, 0) == quic_path_usock(quic_paths(nsk), 0)) {
			/* Take the ALPNs into account, which allows directing the request to
			 * different listening sockets based on the ALPNs.
			 */
			if (!quic_data_cmp(alpns, quic_alpn(nsk))) {
				err = -EADDRINUSE;
				if (sk->sk_reuseport && nsk->sk_reuseport) {
					/* Support SO_REUSEPORT: allow multiple sockets with
					 * same addr/port/ALPNs.
					 */
					err = reuseport_add_sock(sk, nsk, any);
					if (!err) {
						__sk_add_node(sk, &head->head);
						INIT_LIST_HEAD(quic_reqs(sk));
					}
				}
				goto out;
			}
			/* If ALPNs partially match, also consider address in use. */
			if (quic_data_match(alpns, quic_alpn(nsk))) {
				err = -EADDRINUSE;
				goto out;
			}
		}
	}

	if (sk->sk_reuseport) { /* If socket uses reuseport, allocate reuseport group. */
		err = reuseport_alloc(sk, any);
		if (err)
			goto out;
	}
	__sk_add_node(sk, &head->head);
	INIT_LIST_HEAD(quic_reqs(sk));
out:
	spin_unlock_bh(&head->s_lock);
	return err;
}

static void quic_unhash(struct sock *sk)
{
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_request_sock *req, *tmp;
	struct net *net = sock_net(sk);
	struct quic_hash_head *head;
	union quic_addr *sa, *da;

	if (sk_unhashed(sk))
		return;

	sa = quic_path_saddr(paths, 0);
	da = quic_path_daddr(paths, 0);
	if (sk->sk_max_ack_backlog) {
		/* Unhash a listen socket: clean up all pending connection requests. */
		list_for_each_entry_safe(req, tmp, quic_reqs(sk), list) {
			list_del(&req->list);
			quic_request_sock_free(req);
		}
		head = quic_listen_sock_head(net, ntohs(sa->v4.sin_port));
		goto out;
	}
	head = quic_sock_head(net, sa, da);

out:
	spin_lock_bh(&head->s_lock);
	if (rcu_access_pointer(sk->sk_reuseport_cb))
		reuseport_detach_sock(sk); /* If socket was part of a reuseport group, detach it. */
	__sk_del_node_init(sk);
	spin_unlock_bh(&head->s_lock);
}

static int quic_sendmsg(struct sock *sk, struct msghdr *msg, size_t msg_len)
{
	return -EOPNOTSUPP;
}

static int quic_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags,
			int *addr_len)
{
	return -EOPNOTSUPP;
}

/* Wait until a new connection request is available on the listen socket. */
static int quic_wait_for_accept(struct sock *sk, u32 flags)
{
	long timeo = sock_sndtimeo(sk, flags & O_NONBLOCK);
	struct list_head *head = quic_reqs(sk);
	DEFINE_WAIT(wait);
	int err = 0;

	for (;;) {
		if (!list_empty(head))
			break;
		prepare_to_wait_exclusive(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);
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

/* Apply QUIC configuration settings to a socket. */
static int quic_sock_apply_config(struct sock *sk, struct quic_config *c)
{
	struct quic_config *config = quic_config(sk);
	struct quic_packet *packet = quic_packet(sk);
	struct quic_cong *cong = quic_cong(sk);

	if (c->validate_peer_address)
		config->validate_peer_address = c->validate_peer_address;
	if (c->receive_session_ticket)
		config->receive_session_ticket = c->receive_session_ticket;
	if (c->certificate_request)
		config->certificate_request = c->certificate_request;
	if (c->initial_smoothed_rtt) {
		if (c->initial_smoothed_rtt < QUIC_RTT_MIN ||
		    c->initial_smoothed_rtt > QUIC_RTT_MAX)
			return -EINVAL;
		config->initial_smoothed_rtt = c->initial_smoothed_rtt;
		quic_cong_set_srtt(cong, config->initial_smoothed_rtt);
	}
	if (c->plpmtud_probe_interval) {
		if (c->plpmtud_probe_interval < QUIC_MIN_PROBE_TIMEOUT)
			return -EINVAL;
		config->plpmtud_probe_interval = c->plpmtud_probe_interval;
	}
	if (c->payload_cipher_type) {
		if (c->payload_cipher_type != TLS_CIPHER_AES_GCM_128 &&
		    c->payload_cipher_type != TLS_CIPHER_AES_GCM_256 &&
		    c->payload_cipher_type != TLS_CIPHER_AES_CCM_128 &&
		    c->payload_cipher_type != TLS_CIPHER_CHACHA20_POLY1305)
			return -EINVAL;
		config->payload_cipher_type = c->payload_cipher_type;
	}
	if (c->version) {
		config->version = c->version;
		packet->version = c->version;
	}
	if (c->congestion_control_algo) {
		config->congestion_control_algo = c->congestion_control_algo;
		quic_cong_set_algo(cong, config->congestion_control_algo);
	}
	if (c->stream_data_nodelay)
		config->stream_data_nodelay = c->stream_data_nodelay;

	return 0;
}

/* Initialize an accept QUIC socket from a listen socket and a connection request. */
static int quic_copy_sock(struct sock *nsk, struct sock *sk, struct quic_request_sock *req)
{
	struct quic_pnspace *space = quic_pnspace(sk, QUIC_CRYPTO_INITIAL);
	struct quic_transport_param param = {};

	/* Duplicate ALPN from listen to accept socket for handshake. */
	if (quic_data_dup(quic_alpn(nsk), quic_alpn(sk)->data, quic_alpn(sk)->len))
		return -ENOMEM;

	/* Copy socket metadata. */
	nsk->sk_type = sk->sk_type;
	nsk->sk_flags = sk->sk_flags;
	nsk->sk_protocol = IPPROTO_QUIC;
	nsk->sk_backlog_rcv = sk->sk_prot->backlog_rcv;

	nsk->sk_sndbuf = sk->sk_sndbuf;
	nsk->sk_rcvbuf = sk->sk_rcvbuf;
	nsk->sk_rcvtimeo = sk->sk_rcvtimeo;
	nsk->sk_sndtimeo = sk->sk_sndtimeo;
	nsk->sk_bound_dev_if = sk->sk_bound_dev_if;

	inet_sk(nsk)->pmtudisc = inet_sk(sk)->pmtudisc;

	/* Move matching packets from request socket's backlog to accept socket. */
	skb_queue_splice_init(&req->backlog_list, &quic_inq(nsk)->backlog_list);

	/* Record the creation time of this accept socket in microseconds.  Used by
	 * quic_accept_sock_exists() to determine if a packet from sk_backlog of
	 * listen socket predates this socket.
	 */
	space->time = jiffies_to_usecs(jiffies);

	if (sk->sk_family == AF_INET6) /* Set IPv6 specific state if applicable. */
		inet_sk(nsk)->pinet6 = &((struct quic6_sock *)nsk)->inet6;

	quic_inq(nsk)->events = quic_inq(sk)->events;
	quic_paths(nsk)->serv = 1; /* Mark this as a server. */

	/* Copy the QUIC settings and transport parameters to accept socket. */
	quic_sock_apply_config(nsk, quic_config(sk));
	quic_sock_fetch_transport_param(sk, &param);
	quic_sock_apply_transport_param(nsk, &param);

	return 0;
}

/* Finalize setup for an accept QUIC socket. */
static int quic_accept_sock_setup(struct sock *sk, struct quic_request_sock *req)
{
	struct quic_crypto *crypto = quic_crypto(sk, QUIC_CRYPTO_INITIAL);
	struct quic_path_group *paths = quic_paths(sk);
	struct quic_packet *packet = quic_packet(sk);
	struct quic_inqueue *inq = quic_inq(sk);
	struct quic_conn_id conn_id;
	struct sk_buff_head tmpq;
	struct sk_buff *skb;
	int err;

	lock_sock_nested(sk, SINGLE_DEPTH_NESTING);
	/* Set destination address and resolve route (may also auto-set source address). */
	quic_path_set_daddr(paths, 0, &req->daddr);
	err = quic_packet_route(sk);
	if (err < 0)
		goto out;
	quic_set_sk_addr(sk, &req->daddr, false);

	/* Generate and add destination and source connection IDs. */
	quic_conn_id_generate(&conn_id);
	err = quic_conn_id_add(quic_source(sk), &conn_id, 0, sk);
	if (err)
		goto out;
	err = quic_conn_id_add(quic_dest(sk), &req->scid, 0, NULL);
	if (err)
		goto out;

	/* Install initial encryption keys for handshake. */
	err = quic_crypto_set_cipher(crypto, TLS_CIPHER_AES_GCM_128, 0);
	if (err)
		goto out;
	err = quic_crypto_initial_keys_install(crypto, &req->dcid, req->version, 1);
	if (err)
		goto out;
	/* Record the QUIC version offered by the peer. May later change if Compatible Version
	 * Negotiation is triggered.
	 */
	packet->version = req->version;

	/* Save original DCID and retry DCID for building transport parameters, and identifying
	 * the connection in quic_sock_lookup().
	 */
	paths->orig_dcid = req->orig_dcid;
	if (req->retry) {
		paths->retry = 1;
		paths->retry_dcid = req->dcid;
	}

	/* Add socket to hash table, change state to ESTABLISHING, and start idle timer. */
	err = sk->sk_prot->hash(sk);
	if (err)
		goto out;
	quic_set_state(sk, QUIC_SS_ESTABLISHING);
	quic_timer_start(sk, QUIC_TIMER_IDLE, inq->timeout);

	/* Process all packets in backlog list of this socket. */
	__skb_queue_head_init(&tmpq);
	skb_queue_splice_init(&inq->backlog_list, &tmpq);
	skb = __skb_dequeue(&tmpq);
	while (skb) {
		quic_packet_process(sk, skb);
		skb = __skb_dequeue(&tmpq);
	}

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

	nsk = sk_alloc(sock_net(sk), sk->sk_family, GFP_KERNEL, sk->sk_prot, arg->kern);
	if (!nsk) {
		err = -ENOMEM;
		goto out;
	}
	sock_init_data(NULL, nsk);

	req = quic_request_sock_dequeue(sk);

	err = nsk->sk_prot->init(nsk);
	if (err)
		goto free;

	err = quic_copy_sock(nsk, sk, req);
	if (err)
		goto free;
	err = nsk->sk_prot->bind(nsk, &req->saddr.sa, sizeof(req->saddr));
	if (err)
		goto free;

	err = quic_accept_sock_setup(nsk, req);
	if (err)
		goto free;

	quic_request_sock_free(req);
out:
	release_sock(sk);
	arg->err = err;
	return nsk;
free:
	quic_request_sock_free(req);
	nsk->sk_prot->close(nsk, 0);
	nsk = NULL;
	goto out;
}

static void quic_close(struct sock *sk, long timeout)
{
	lock_sock_nested(sk, SINGLE_DEPTH_NESTING);

	quic_outq_transmit_app_close(sk);
	quic_set_state(sk, QUIC_SS_CLOSED);
	sk->sk_prot->unhash(sk);

	release_sock(sk);

	sk_common_release(sk);
}

static int quic_do_setsockopt(struct sock *sk, int optname, sockptr_t optval, unsigned int optlen)
{
	return -EOPNOTSUPP;
}

static int quic_setsockopt(struct sock *sk, int level, int optname,
			   sockptr_t optval, unsigned int optlen)
{
	if (level != SOL_QUIC)
		return quic_common_setsockopt(sk, level, optname, optval, optlen);

	return quic_do_setsockopt(sk, optname, optval, optlen);
}

/**
 * quic_kernel_setsockopt - set a QUIC socket option from within the kernel
 * @sk: socket to configure
 * @optname: option name (QUIC-level)
 * @optval: pointer to the option value
 * @optlen: size of the option value
 *
 * Sets a QUIC socket option on a kernel socket without involving user space.
 *
 * Return:
 * - On success, 0 is returned.
 * - On error, a negative error value is returned.
 */
int quic_kernel_setsockopt(struct sock *sk, int optname, void *optval, unsigned int optlen)
{
	return quic_do_setsockopt(sk, optname, KERNEL_SOCKPTR(optval), optlen);
}
EXPORT_SYMBOL_GPL(quic_kernel_setsockopt);

static int quic_do_getsockopt(struct sock *sk, int optname, sockptr_t optval, sockptr_t optlen)
{
	return -EOPNOTSUPP;
}

static int quic_getsockopt(struct sock *sk, int level, int optname,
			   char __user *optval, int __user *optlen)
{
	if (level != SOL_QUIC)
		return quic_common_getsockopt(sk, level, optname, optval, optlen);

	return quic_do_getsockopt(sk, optname, USER_SOCKPTR(optval), USER_SOCKPTR(optlen));
}

/**
 * quic_kernel_getsockopt - get a QUIC socket option from within the kernel
 * @sk: socket to query
 * @optname: option name (QUIC-level)
 * @optval: pointer to the buffer to receive the option value
 * @optlen: pointer to the size of the buffer; updated to actual length on return
 *
 * Gets a QUIC socket option from a kernel socket, bypassing user space.
 *
 * Return:
 * - On success, 0 is returned.
 * - On error, a negative error value is returned.
 */
int quic_kernel_getsockopt(struct sock *sk, int optname, void *optval, unsigned int *optlen)
{
	return quic_do_getsockopt(sk, optname, KERNEL_SOCKPTR(optval), KERNEL_SOCKPTR(optlen));
}
EXPORT_SYMBOL_GPL(quic_kernel_getsockopt);

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
	if (flags & QUIC_F_TSQ_DEFERRED) {
		quic_timer_pace_handler(sk);
		__sock_put(sk);
	}
}

static int quic_disconnect(struct sock *sk, int flags)
{
	quic_set_state(sk, QUIC_SS_CLOSED); /* for a listen socket only */
	return 0;
}

static void quic_shutdown(struct sock *sk, int how)
{
	if (!(how & SEND_SHUTDOWN))
		goto out;

	quic_outq_transmit_app_close(sk);
out:
	quic_set_state(sk, QUIC_SS_CLOSED);
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
	.backlog_rcv	=  quic_packet_process,
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
	.backlog_rcv	=  quic_packet_process,
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
