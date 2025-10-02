#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Testing For SCTP DTLS.
# TOPO: CLIENT_NS (veth1) <---> (veth1) -> SERVER_NS

source lib.sh
CLIENT_IP4="10.0.0.1"
CLIENT_IP6="2000::1"
CLIENT_PORT=1234

SERVER_IP4="10.0.0.2"
SERVER_IP6="2000::2"
SERVER_PORT=1234

setup() {
	modprobe sctp
	modprobe sctp_diag
	setup_ns CLIENT_NS SERVER_NS

	ip net exec $CLIENT_NS sysctl -wq net.ipv6.conf.default.accept_dad=0
	ip net exec $SERVER_NS sysctl -wq net.ipv6.conf.default.accept_dad=0

	ip -n $SERVER_NS link add veth1 type veth peer name veth1 netns \
		$CLIENT_NS

	ip -n $CLIENT_NS link set veth1 up
	ip -n $CLIENT_NS addr add $CLIENT_IP4/24 dev veth1
	ip -n $CLIENT_NS addr add $CLIENT_IP6/24 dev veth1

	ip -n $SERVER_NS link set veth1 up
	ip -n $SERVER_NS addr add $SERVER_IP4/24 dev veth1
	ip -n $SERVER_NS addr add $SERVER_IP6/24 dev veth1
}

cleanup() {
	ip netns exec $SERVER_NS pkill -x sctp_dtls
	cleanup_ns $CLIENT_NS $SERVER_NS
}

do_test() {
	local CNT=0

	ip netns exec $SERVER_NS ./sctp_dtls server $AF $SERVER_IP \
		$SERVER_PORT > /dev/null 2>&1 &
	disown

	until ip netns exec $SERVER_NS ss -lS src \
		$SERVER_IP:$SERVER_PORT | grep -q LISTEN; do
		[ $((CNT++)) = "20" ] && { RET=3; return $RET; }
		sleep 0.1
	done

	timeout 5 ip netns exec $CLIENT_NS ./sctp_dtls client $AF \
		$SERVER_IP $SERVER_PORT
	RET=$?
	return $RET
}

trap cleanup EXIT
setup && echo "Testing For SCTP DTLS:" && \
CLIENT_IP=$CLIENT_IP4 SERVER_IP=$SERVER_IP4 AF="-4" do_test && \
echo "***v4 Tests Done***" && \
CLIENT_IP=$CLIENT_IP6 SERVER_IP=$SERVER_IP6 AF="-6" do_test && \
echo "***v6 Tests Done***"
exit $?
