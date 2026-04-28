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
	return -EOPNOTSUPP;
}

static int quic_connect(struct sock *sk, struct sockaddr_unsized *addr,
			int addr_len)
{
	return -EOPNOTSUPP;
}

static int quic_hash(struct sock *sk)
{
	return 0;
}

static void quic_unhash(struct sock *sk)
{
}

static int quic_sendmsg(struct sock *sk, struct msghdr *msg, size_t msg_len)
{
	return -EOPNOTSUPP;
}

static int quic_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
			int flags)
{
	return -EOPNOTSUPP;
}

static struct sock *quic_accept(struct sock *sk, struct proto_accept_arg *arg)
{
	arg->err = -EOPNOTSUPP;
	return NULL;
}

static void quic_close(struct sock *sk, long timeout)
{
	lock_sock(sk);

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
}

static int quic_disconnect(struct sock *sk, int flags)
{
	return -EOPNOTSUPP;
}

static void quic_shutdown(struct sock *sk, int how)
{
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
