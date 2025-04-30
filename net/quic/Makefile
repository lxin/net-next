# SPDX-License-Identifier: GPL-2.0-or-later
#
# Makefile for QUIC support code.
#

obj-$(CONFIG_IP_QUIC) += quic.o

quic-y := common.o family.o protocol.o socket.o stream.o connid.o path.o \
	  cong.o pnspace.o crypto.o timer.o frame.o packet.o outqueue.o \
	  inqueue.o

obj-$(CONFIG_IP_QUIC_TEST) += quic_sample_test.o

quic_sample_test-y := sample_test.o
