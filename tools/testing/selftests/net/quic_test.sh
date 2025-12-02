#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

NUM_NETIFS=2
source forwarding/lib.sh

host_create()
{
	cveth=${NETIFS[p1]}
	sveth=${NETIFS[p2]}

	simple_if_init $cveth 192.0.2.1/24 2001:db8:1::1/64
	simple_if_init $sveth 192.0.2.2/24 2001:db8:1::2/64
}

host_destroy()
{
	simple_if_fini $cveth 192.0.2.1/24 2001:db8:1::1/64
	simple_if_fini $sveth 192.0.2.2/24 2001:db8:1::2/64
}

daemon_run()
{
	$@ > /dev/null 2>&1 &
}

server_run()
{
	local CNT=0

	$@ > /dev/null 2>&1 &
	while ! grep -q ":1234" /proc/net/quic/eps; do
		[ $((CNT++)) -eq 30 ] && return 1
		sleep 0.1;
	done
}

client_run()
{
	local CNT=0

	$@ || return $?
	while grep -q ":1234" /proc/net/quic/eps; do
		[ $((CNT++)) -eq 30 ] && return 1
		sleep 0.1;
	done
}

cleanup()
{
	pkill -f "quic_test "
	pkill -f "quic_sample_test"
	[ -d /sys/module/quic_sample_test ] && rmmod quic_sample_test
	[ "$unload" = "1" -a -d /sys/module/quic ] && rmmod quic
	ip link set $cveth mtu 1500
	ip link set $sveth mtu 1500
	host_destroy
}

trap cleanup EXIT

[ -d /sys/module/quic ] || unload=1

do_test()
{
	local addr="192.0.2.2"
	local port=1234
	local af=$1

	[ "$af" = "6" ] && addr="2001:db8:1::2"

	echo "## IPv$af ##"

	echo "1. Functional Test:"
	client_run ./quic_test func $addr $port $cveth $sveth || return $?
	echo ""

	echo "2. Performance Test:"
	for mtu in 1500 9000 65535; do
		ip link set $cveth mtu $mtu || return $?
		ip link set $sveth mtu $mtu || return $?
		for size in 256 1024 4096 16384 65536; do
			echo "=> MTU = $mtu (Message size = $size)"
			server_run ./quic_test perf server $size $addr $port \
				$sveth || return $?
			client_run ./quic_test perf client $size $addr $port \
				$cveth || return $?
		done
	done
	ip link set $cveth mtu 1500
	ip link set $sveth mtu 1500
	echo ""

	echo "3. Sample Test:"
	echo "=> Userspace -> Userspace"
	server_run ./quic_test sample server $addr $port $sveth || return $?
	client_run ./quic_test sample client $addr $port $cveth || return $?

	if modprobe -nq quic_sample_test; then
		echo "=> Userspace -> Kernel"
		daemon_run ./quic_test tlshd 2
		server_run modprobe quic_sample_test role=server ip=$addr \
			port=$port dev=$sveth || return $?
		client_run ./quic_test sample client $addr $port $cveth || \
			return $?
		rmmod quic_sample_test

		echo "=> Kernel -> Userspace"
		server_run ./quic_test sample server $addr $port $sveth || \
			return $?
		client_run modprobe quic_sample_test role=client ip=$addr \
			port=$port dev=$cveth || return $?
		rmmod quic_sample_test
		dmesg | tail -n 5
		sleep 1
	fi
	echo ""

	echo "4. Ticket Test:"
	echo "=> Userspace -> Userspace"
	server_run ./quic_test ticket server $addr $port $sveth || return $?
	client_run ./quic_test ticket client $addr $port $cveth || return $?

	if modprobe -nq quic_sample_test; then
		echo "=> Userspace -> Kernel"
		daemon_run ./quic_test tlshd 4
		server_run modprobe quic_sample_test alpn=ticket role=server \
			ip=$addr port=$port dev=$sveth || return $?
		client_run ./quic_test ticket client $addr $port $cveth || \
			return $?
		rmmod quic_sample_test

		echo "=> Kernel -> Userspace"
		server_run ./quic_test ticket server $addr $port $sveth || \
			return $?
		client_run modprobe quic_sample_test alpn=ticket role=client \
			ip=$addr port=$port dev=$cveth || return $?
		rmmod quic_sample_test
		dmesg | tail -n 9
		sleep 1
	fi
	echo ""
}

host_create || exit $?

do_test 4 || exit $?
do_test 6 || exit $?

! [ "$unload" = "1" -a -d /sys/module/quic ] || rmmod quic
