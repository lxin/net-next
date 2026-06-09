// SPDX-License-Identifier: GPL-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/sctp.h>

static uint8_t sdk_keys_1[16 + 12 + 16] = {
	/* key */
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	/* iv */
	0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
	0x12, 0x34, 0x56, 0x78,
	/* sn_key */
	0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18,
	0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90,
};

static struct sctp_dtls_keys dtls_key_1 = {
	.sdk_cipher_suite = {0x13, 0x01},
	.sdk_epoch = 4,
	.sdk_restart = 0,
	.sdk_key_len = 16,
	.sdk_iv_len = 12,
	.sdk_sn_key_len = 16,
};

static struct sctp_dtls_keys_id dtls_key_id_1 = {
	.sdki_epoch = 4,
	.sdki_restart = 0,
};

static uint8_t sdk_keys_2[32 + 12 + 32] = {
	/* key */
	0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
	0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	/* iv */
	0xba, 0xad, 0xf0, 0x0d, 0xfe, 0xed, 0xfa, 0xce,
	0x11, 0x22, 0x33, 0x44,
	/* sn_key */
	0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
	0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01,
	0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89,
	0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xfa, 0xfb,
};

static struct sctp_dtls_keys dtls_key_2 = {
	.sdk_cipher_suite = {0x13, 0x03},
	.sdk_epoch = 5,
	.sdk_restart = 0,
	.sdk_key_len = 32,
	.sdk_iv_len = 12,
	.sdk_sn_key_len = 32,
};

static uint8_t sdk_keys_r[16 + 12 + 16] = {
	/* key */
	0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
	0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
	/* iv */
	0x13, 0x37, 0x42, 0x24, 0xbe, 0xad, 0xde, 0xad,
	0xfa, 0xce, 0xb0, 0x0c,
	/* sn_key */
	0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
};

static struct sctp_dtls_keys dtls_key_r = {
	.sdk_cipher_suite = {0x13, 0x04},
	.sdk_epoch = 4,
	.sdk_restart = 1,
	.sdk_key_len = 16,
	.sdk_iv_len = 12,
	.sdk_sn_key_len = 16,
};


static int set_send_keys_1(int sk)
{
	struct sctp_dtls_keys *key;
	uint8_t buf[128] = {};

	key = (struct sctp_dtls_keys *)buf;
	memcpy(key, &dtls_key_1, sizeof(dtls_key_1));
	memcpy(key + 1, sdk_keys_1, sizeof(sdk_keys_1));

	if (setsockopt(sk, IPPROTO_SCTP, SCTP_DTLS_SET_SEND_KEYS,
		       key, sizeof(*key) + sizeof(sdk_keys_1))) {
		printf("failed to setsockopt SCTP_DTLS_SET_SEND_KEYS\n");
		return -1;
	}
	return 0;
}

static int set_recv_keys_1(int sk)
{
	struct sctp_dtls_keys *key;
	uint8_t buf[128] = {};

	key = (struct sctp_dtls_keys *)buf;
	memcpy(key, &dtls_key_1, sizeof(dtls_key_1));
	memcpy(key + 1, sdk_keys_1, sizeof(sdk_keys_1));

	if (setsockopt(sk, IPPROTO_SCTP, SCTP_DTLS_ADD_RECV_KEYS,
		       key, sizeof(*key) + sizeof(sdk_keys_1))) {
		printf("failed to setsockopt SCTP_DTLS_ADD_RECV_KEYS\n");
		return -1;
	}

	return 0;
}

static int __attribute__((unused)) del_recv_keys_1(int sk)
{
	if (setsockopt(sk, IPPROTO_SCTP, SCTP_DTLS_DEL_RECV_KEYS,
		       &dtls_key_id_1, sizeof(dtls_key_id_1))) {
		printf("failed to setsockopt SCTP_DTLS_ADD_RECV_KEYS\n");
		return -1;
	}
	return 0;
}

static int __attribute__((unused)) set_send_keys_2(int sk)
{
	struct sctp_dtls_keys *key;
	uint8_t buf[128] = {};

	key = (struct sctp_dtls_keys *)buf;
	memcpy(key, &dtls_key_2, sizeof(dtls_key_2));
	memcpy(key + 1, sdk_keys_2, sizeof(sdk_keys_2));

	if (setsockopt(sk, IPPROTO_SCTP, SCTP_DTLS_SET_SEND_KEYS,
		       key, sizeof(*key) + sizeof(sdk_keys_2))) {
		printf("failed to setsockopt SCTP_DTLS_SET_SEND_KEYS\n");
		return -1;
	}
	return 0;
}

static int __attribute__((unused)) set_recv_keys_2(int sk)
{
	struct sctp_dtls_keys *key;
	uint8_t buf[128] = {};

	key = (struct sctp_dtls_keys *)buf;
	memcpy(key, &dtls_key_2, sizeof(dtls_key_2));
	memcpy(key + 1, sdk_keys_2, sizeof(sdk_keys_2));

	if (setsockopt(sk, IPPROTO_SCTP, SCTP_DTLS_ADD_RECV_KEYS,
		       key, sizeof(*key) + sizeof(sdk_keys_2))) {
		printf("failed to setsockopt SCTP_DTLS_ADD_RECV_KEYS\n");
		return -1;
	}
	return 0;
}

static int set_send_keys_r(int sk)
{
	struct sctp_dtls_keys *key;
	uint8_t buf[128] = {};

	key = (struct sctp_dtls_keys *)buf;
	memcpy(key, &dtls_key_r, sizeof(dtls_key_r));
	memcpy(key + 1, sdk_keys_r, sizeof(sdk_keys_r));

	if (setsockopt(sk, IPPROTO_SCTP, SCTP_DTLS_SET_SEND_KEYS,
		       key, sizeof(*key) + sizeof(sdk_keys_r))) {
		printf("failed to setsockopt SCTP_DTLS_SET_SEND_KEYS\n");
		return -1;
	}
	return 0;
}

static int set_recv_keys_r(int sk)
{
	struct sctp_dtls_keys *key;
	uint8_t buf[128] = {};

	key = (struct sctp_dtls_keys *)buf;
	memcpy(key, &dtls_key_r, sizeof(dtls_key_r));
	memcpy(key + 1, sdk_keys_r, sizeof(sdk_keys_r));

	if (setsockopt(sk, IPPROTO_SCTP, SCTP_DTLS_ADD_RECV_KEYS,
		       key, sizeof(*key) + sizeof(sdk_keys_r))) {
		printf("failed to setsockopt SCTP_DTLS_ADD_RECV_KEYS\n");
		return -1;
	}
	return 0;
}

static int set_restart_keys(int csk)
{
	if (set_send_keys_r(csk))
		return -1;
	if (set_recv_keys_r(csk))
		return -1;
	printf("Restart Keys Setting\n");
	return 0;
}

static void set_addr(struct sockaddr_storage *ss, char *ip, char *port,
		     unsigned int *len)
{
	if (ss->ss_family == AF_INET) {
		struct sockaddr_in *a = (struct sockaddr_in *)ss;

		a->sin_addr.s_addr = inet_addr(ip);
		a->sin_port = htons(atoi(port));
		*len = sizeof(*a);
	} else {
		struct sockaddr_in6 *a = (struct sockaddr_in6 *)ss;

		a->sin6_family = AF_INET6;
		inet_pton(AF_INET6, ip, &a->sin6_addr);
		a->sin6_port = htons(atoi(port));
		*len = sizeof(*a);
	}
}

static int set_local_config(int sk)
{
	struct sctp_dtls_config *p;
	uint8_t buf[20] = {};
	socklen_t len;

	len = sizeof(buf);
	p = (struct sctp_dtls_config *)buf;
	/* DTLS Chunk with Pre-shared cryptographic parameters. */
	p->sdc_pmids[0] = 0;
	p->sdc_flags = (SCTP_DTLS_CLIENT | SCTP_DTLS_SERVER |
			SCTP_DTLS_RESTART | SCTP_DTLS_REQUIRED);
	p->sdc_nr_pmids = 1;

	if (setsockopt(sk, IPPROTO_SCTP, SCTP_DTLS_LOCAL_CONFIG, p, len)) {
		printf("failed to setsockopt SCTP_DTLS_LOCAL_CONFIG\n");
		return -1;
	}
	if (getsockopt(sk, IPPROTO_SCTP, SCTP_DTLS_LOCAL_CONFIG, p, &len)) {
		printf("failed to getsockopt SCTP_DTLS_LOCAL_CONFIG\n");
		return -1;
	}
	printf("Local config nr_pmids %u flags 0x%x\n", p->sdc_nr_pmids,
	       p->sdc_flags);
	return 0;
}

static int set_replay_window(int sk)
{
	struct sctp_assoc_value v = {};
	socklen_t len;

	v.assoc_value = 64;
	len = sizeof(v);
	if (setsockopt(sk, IPPROTO_SCTP, SCTP_DTLS_REPLAY_WINDOW, &v, len)) {
		printf("failed to setsockopt SCTP_DTLS_REPLAY_WINDOW\n");
		return -1;
	}
	if (getsockopt(sk, IPPROTO_SCTP, SCTP_DTLS_REPLAY_WINDOW, &v, &len)) {
		printf("failed to getsockopt SCTP_DTLS_REPLAY_WINDOW\n");
		return -1;
	}
	printf("Replay window %u\n", v.assoc_value);
	return 0;
}

static int get_chosen_config(int sk)
{
	struct sctp_dtls_config *p;
	uint8_t buf[128] = {};
	socklen_t len;

	len = sizeof(buf);
	p = (struct sctp_dtls_config *)buf;

	if (getsockopt(sk, IPPROTO_SCTP, SCTP_DTLS_GET_CONFIG, p, &len)) {
		printf("failed to getsockopt SCTP_DTLS_GET_CONFIG\n");
		return -1;
	}

	if (p->sdc_flags & SCTP_DTLS_CLIENT)
		printf("This is CLIENT role\n");
	if (p->sdc_flags & SCTP_DTLS_SERVER)
		printf("This is SERVER role\n");
	return 0;
}

static int get_stats(int sk)
{
	struct sctp_dtls_stats s = {};
	socklen_t len;

	len = sizeof(s);
	if (getsockopt(sk, IPPROTO_SCTP, SCTP_DTLS_GET_STATS, &s, &len)) {
		printf("failed to getsockopt SCTP_DTLS_GET_STATS\n");
		return -1;
	}

	printf("STATS: drop %llu, fail %llu, recv %llu,  send %llu\n",
	       s.sds_dropped_unprotected, s.sds_aead_failures,
	       s.sds_recv_protected, s.sds_sent_protected);
	return 0;
}

static int get_km_params(int sk)
{
	struct sctp_dtls_kmp *p;
	uint8_t buf[128] = {};
	socklen_t len;

	len = sizeof(buf);
	p = (struct sctp_dtls_kmp *)buf;

	if (getsockopt(sk, IPPROTO_SCTP, SCTP_DTLS_GET_LOCAL_KM_PARAM,
		       p, &len)) {
		printf("failed to getsockopt SCTP_DTLS_GET_LOCAL_KM_PARAM\n");
		return -1;
	}
	printf("Local km_param bytes %u\n", p->sdk_nr_bytes);
	len = sizeof(buf);
	if (getsockopt(sk, IPPROTO_SCTP, SCTP_DTLS_GET_PEER_KM_PARAM,
		       p, &len)) {
		printf("failed to getsockopt SCTP_DTLS_GET_PEER_KM_PARAM\n");
		return -1;
	}
	printf("Peer km_param bytes %u\n", p->sdk_nr_bytes);
	return 0;
}

static int set_enforce_protection(int sk)
{
	struct sctp_assoc_value params = {};
	socklen_t len;

	len = sizeof(params);
	params.assoc_value = 1;
	if (setsockopt(sk, IPPROTO_SCTP, SCTP_DTLS_ENFORCE_PROTECTION,
		       &params, len)) {
		printf("failed to setsockopt SCTP_DTLS_ENFORCE_PROTECTION\n");
		return -1;
	}
	if (getsockopt(sk, IPPROTO_SCTP, SCTP_DTLS_ENFORCE_PROTECTION,
		       &params, &len)) {
		printf("failed to getsockopt SCTP_DTLS_GET_CONFIG\n");
		return -1;
	}
	printf("Enfore protection %u\n", params.assoc_value);

	return 0;
}

#define MAX_CNT		128
#define MSG_LEN		4096
static char msg[MSG_LEN];

static int do_client(int argc, char *argv[])
{
	struct sockaddr_storage remote = {};
	unsigned int len;
	int csk, ret, i;

	if (argc < 5) {
		printf("%s client -4|6 IP PORT\n", argv[0]);
		return -1;
	}

	remote.ss_family = !strcmp(argv[2], "-4") ? AF_INET : AF_INET6;
	csk = socket(remote.ss_family, SOCK_STREAM, IPPROTO_SCTP);
	if (csk < 0) {
		printf("failed to create socket\n");
		return -1;
	}

	if (set_local_config(csk))
		return -1;
	if (set_replay_window(csk))
		return -1;

	set_addr(&remote, argv[3], argv[4], &len);
	ret = connect(csk, (struct sockaddr *)&remote, len);
	if (ret < 0) {
		printf("failed to connect to peer\n");
		return -1;
	}

	if (get_chosen_config(csk))
		return -1;
	if (get_km_params(csk))
		return -1;
	if (set_recv_keys_1(csk))
		return -1;
	if (set_send_keys_1(csk))
		return -1;
	if (set_enforce_protection(csk))
		return -1;

	for (i = 0; i < MAX_CNT; i++) {
		ret = send(csk, msg, sizeof(msg), 0);
		if (ret < 0) {
			printf("failed to send msg\n");
			return -1;
		}
		printf("send data %d\n", ret);
	}

	if (get_stats(csk))
		return -1;

	close(csk);

	return 0;
}

static int do_server(int argc, char *argv[])
{
	struct sockaddr_storage remote;
	int lsk, csk, ret;
	unsigned int len;

	if (argc < 5) {
		printf("%s server -4|6 IP PORT\n", argv[0]);
		return -1;
	}

	remote.ss_family = !strcmp(argv[2], "-4") ? AF_INET : AF_INET6;
	lsk = socket(remote.ss_family, SOCK_STREAM, IPPROTO_SCTP);
	if (lsk < 0) {
		printf("failed to create lsk\n");
		return -1;
	}

	if (argc >= 6) {
		ret = setsockopt(lsk, SOL_SOCKET, SO_BINDTODEVICE,
				argv[5], strlen(argv[5]) + 1);
		if (ret < 0) {
			printf("failed to bind to device\n");
			return -1;
		}
	}

	set_addr(&remote, argv[3], argv[4], &len);
	ret = bind(lsk, (struct sockaddr *)&remote, len);
	if (ret < 0) {
		printf("failed to bind to address\n");
		return -1;
	}

	if (set_local_config(lsk))
		return -1;
	if (set_replay_window(lsk))
		return -1;

	ret = listen(lsk, 5);
	if (ret < 0) {
		printf("failed to listen on port\n");
		return -1;
	}

	csk = accept(lsk, (struct sockaddr *)NULL, (socklen_t *)NULL);
	if (csk < 0) {
		printf("failed to accept new client\n");
		return -1;
	}

	if (set_restart_keys(csk))
		return -1;
	if (get_chosen_config(csk))
		return -1;
	if (get_km_params(csk))
		return -1;
	if (set_send_keys_1(csk))
		return -1;
	if (set_recv_keys_1(csk))
		return -1;
	if (set_enforce_protection(csk))
		return -1;

	while (1) {
		ret = recv(csk, msg, sizeof(msg), 0);
		if (ret < 0) {
			printf("failed to recv msg\n");
			return -1;
		}
		if (ret == 0) {
			printf("association is closed\n");
			break;
		}
		printf("recv data %d\n", ret);
	}

	close(csk);
	close(lsk);

	return 0;
}

int main(int argc, char *argv[])
{
	if (argc < 2 ||
	    (strcmp(argv[1], "server") && strcmp(argv[1], "client"))) {
		printf("%s server|client ...\n", argv[0]);
		return -1;
	}

	if (!strcmp(argv[1], "client"))
		return do_client(argc, argv);

	return do_server(argc, argv);
}
