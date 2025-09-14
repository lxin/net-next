// SPDX-License-Identifier: GPL-2.0-or-later
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2023
 *
 * This file is part of the QUIC kernel implementation
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#ifndef _LINUX_QUIC_CRYPTO_H
#define _LINUX_QUIC_CRYPTO_H

#include <linux/netdevice.h>

#define MAX_CONN_ID_SIZE	20
#define MAX_KEY_SIZE		32
#define IV_SIZE			12

enum quic_crypto_dir {
	QUIC_CRYPTO_DIR_RX,
	QUIC_CRYPTO_DIR_TX,
};

struct quic_crypto_info {
	struct sockaddr_storage daddr;
	struct sockaddr_storage saddr;
	u8 conn_id[MAX_CONN_ID_SIZE];
	u8 conn_id_len;

	u8 data_key[MAX_KEY_SIZE];
	u8 hdr_key[MAX_KEY_SIZE];
	u8 iv[IV_SIZE];
	u16 cipher;
};

struct quicdev_ops {
	int (*quic_dev_add)(struct net_device *dev,
			    enum quic_crypto_dir dir,
			    struct quic_crypto_info *info);

	void (*quic_dev_del)(struct net_device *dev,
			     enum quic_crypto_dir dir,
			     struct quic_crypto_info *info);
};

#endif /* _LINUX_QUIC_CRYPTO_H */
