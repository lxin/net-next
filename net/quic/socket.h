/* SPDX-License-Identifier: GPL-2.0-or-later */
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#include <net/udp_tunnel.h>
#include <linux/quic.h>

#include "common.h"
#include "family.h"
#include "stream.h"
#include "connid.h"
#include "path.h"

#include "protocol.h"

extern struct proto quic_prot;
extern struct proto quicv6_prot;

enum quic_state {
	QUIC_SS_CLOSED		= TCP_CLOSE,
	QUIC_SS_LISTENING	= TCP_LISTEN,
	QUIC_SS_ESTABLISHING	= TCP_SYN_RECV,
	QUIC_SS_ESTABLISHED	= TCP_ESTABLISHED,
};

struct quic_sock {
	struct inet_sock		inet;
	struct list_head		reqs;

	struct quic_config		config;
	struct quic_data		ticket;
	struct quic_data		token;
	struct quic_data		alpn;

	struct quic_stream_table	streams;
	struct quic_conn_id_set		source;
	struct quic_conn_id_set		dest;
	struct quic_path_group		paths;
};

struct quic6_sock {
	struct quic_sock	quic;
	struct ipv6_pinfo	inet6;
};

static inline struct quic_sock *quic_sk(const struct sock *sk)
{
	return (struct quic_sock *)sk;
}

static inline struct list_head *quic_reqs(const struct sock *sk)
{
	return &quic_sk(sk)->reqs;
}

static inline struct quic_config *quic_config(const struct sock *sk)
{
	return &quic_sk(sk)->config;
}

static inline struct quic_data *quic_token(const struct sock *sk)
{
	return &quic_sk(sk)->token;
}

static inline struct quic_data *quic_ticket(const struct sock *sk)
{
	return &quic_sk(sk)->ticket;
}

static inline struct quic_data *quic_alpn(const struct sock *sk)
{
	return &quic_sk(sk)->alpn;
}

static inline struct quic_stream_table *quic_streams(const struct sock *sk)
{
	return &quic_sk(sk)->streams;
}

static inline struct quic_conn_id_set *quic_source(const struct sock *sk)
{
	return &quic_sk(sk)->source;
}

static inline struct quic_conn_id_set *quic_dest(const struct sock *sk)
{
	return &quic_sk(sk)->dest;
}

static inline struct quic_path_group *quic_paths(const struct sock *sk)
{
	return &quic_sk(sk)->paths;
}

static inline bool quic_is_serv(const struct sock *sk)
{
	return quic_paths(sk)->serv;
}

static inline bool quic_is_establishing(struct sock *sk)
{
	return sk->sk_state == QUIC_SS_ESTABLISHING;
}

static inline bool quic_is_established(struct sock *sk)
{
	return sk->sk_state == QUIC_SS_ESTABLISHED;
}

static inline bool quic_is_listen(struct sock *sk)
{
	return sk->sk_state == QUIC_SS_LISTENING;
}

static inline bool quic_is_closed(struct sock *sk)
{
	return sk->sk_state == QUIC_SS_CLOSED;
}

static inline void quic_set_state(struct sock *sk, int state)
{
	struct net *net = sock_net(sk);
	int mib;

	if (sk->sk_state == state)
		return;

	if (state == QUIC_SS_ESTABLISHED) {
		mib = quic_is_serv(sk) ? QUIC_MIB_CONN_PASSIVEESTABS
				       : QUIC_MIB_CONN_ACTIVEESTABS;
		QUIC_INC_STATS(net, mib);
		QUIC_INC_STATS(net, QUIC_MIB_CONN_CURRENTESTABS);
	} else if (quic_is_established(sk)) {
		QUIC_DEC_STATS(net, QUIC_MIB_CONN_CURRENTESTABS);
	}

	inet_sk_set_state(sk, state);
	sk->sk_state_change(sk);
}
