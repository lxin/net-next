.. SPDX-License-Identifier: GPL-2.0

=================
Linux Kernel QUIC
=================

Introduction
============

The QUIC protocol, defined in RFC 9000, is a secure, multiplexed transport
built on top of UDP. It enables low-latency connection establishment,
stream-based communication with flow control, and supports connection
migration across network paths, while ensuring confidentiality, integrity,
and availability.

This implementation introduces QUIC support in Linux Kernel, offering
several key advantages:

- **In-Kernel QUIC Support for Subsystems**: Enables kernel subsystems
  such as SMB and NFS to operate over QUIC with minimal changes. Once the
  handshake is complete via the net/handshake APIs, data exchange proceeds
  over standard in-kernel transport interfaces.

- **Standard Socket API Semantics**: Implements core socket operations
  (listen(), accept(), connect(), sendmsg(), recvmsg(), close(),
  getsockopt(), setsockopt(), getsockname(), and getpeername()),
  allowing user space to interact with QUIC sockets in a familiar,
  POSIX-compliant way.

- **ALPN-Based Connection Dispatching**: Supports in-kernel ALPN
  (Application-Layer Protocol Negotiation) routing, allowing demultiplexing
  of QUIC connections across different user-space processes based
  on the ALPN identifiers.

- **Performance Enhancements**: Handles all control messages in-kernel
  to reduce syscall overhead, incorporates zero-copy mechanisms such as
  sendfile() minimize data movement, and is also structured to support
  future crypto hardware offloads.

This implementation offers fundamental support for the following RFCs:

- RFC9000 - QUIC: A UDP-Based Multiplexed and Secure Transport
- RFC9001 - Using TLS to Secure QUIC
- RFC9002 - QUIC Loss Detection and Congestion Control
- RFC9221 - An Unreliable Datagram Extension to QUIC
- RFC9287 - Greasing the QUIC Bit
- RFC9368 - Compatible Version Negotiation for QUIC
- RFC9369 - QUIC Version 2

The socket APIs for QUIC follow the RFC draft [1]_:

- The Sockets API Extensions for In-kernel QUIC Implementations

Implementation
==============

The central design is to implement QUIC within the kernel while delegating
the handshake to userspace.

Only the processing and creation of raw TLS Handshake Messages are handled
in userspace, facilitated by a TLS library like GnuTLS. These messages are
exchanged between kernel and userspace via sendmsg() and recvmsg(), with
cryptographic details conveyed through control messages (cmsg).

The entire QUIC protocol, aside from the TLS Handshake Messages processing
and creation, is managed within the kernel. Rather than using a Upper Layer
Protocol (ULP) layer, this implementation establishes a socket of type
IPPROTO_QUIC (similar to IPPROTO_MPTCP), operating over UDP tunnels.

For kernel consumers, they can initiate a handshake request from the kernel
to userspace using the existing net/handshake netlink. The userspace
component, such as tlshd service [2]_, then manages the processing
of the QUIC handshake request.

Handshake Architecture
----------------------

::

  ┌──────┐  ┌──────┐
  │ APP1 │  │ APP2 │ ...
  └──────┘  └──────┘
  ┌──────────────────────────────────────────┐
  │     {quic_client/server_handshake()}     │<─────────────┐
  └──────────────────────────────────────────┘       ┌─────────────┐
   {send/recvmsg()}      {set/getsockopt()}          │    tlshd    │
   [CMSG handshake_info] [SOCKOPT_CRYPTO_SECRET]     └─────────────┘
                         [SOCKOPT_TRANSPORT_PARAM_EXT]    │   ^
                │ ^                  │ ^                  │   │
  Userspace     │ │                  │ │                  │   │
  ──────────────│─│──────────────────│─│──────────────────│───│───────
  Kernel        │ │                  │ │                  │   │
                v │                  v │                  v   │
  ┌──────────────────┬───────────────────────┐       ┌─────────────┐
  │ protocol, timer, │ socket (IPPROTO_QUIC) │<──┐   │ handshake   │
  │                  ├───────────────────────┤   │   │netlink APIs │
  │ common, family,  │ outqueue  |  inqueue  │   │   └─────────────┘
  │                  ├───────────────────────┤   │      │       │
  │ stream, connid,  │         frame         │   │   ┌─────┐ ┌─────┐
  │                  ├───────────────────────┤   │   │     │ │     │
  │ path, pnspace,   │         packet        │   │───│ SMB │ │ NFS │...
  │                  ├───────────────────────┤   │   │     │ │     │
  │ cong, crypto     │       UDP tunnels     │   │   └─────┘ └─────┘
  └──────────────────┴───────────────────────┘   └──────┴───────┘

User Data Architecture
----------------------

::

  ┌──────┐  ┌──────┐
  │ APP1 │  │ APP2 │ ...
  └──────┘  └──────┘
   {send/recvmsg()}   {set/getsockopt()}              {recvmsg()}
   [CMSG stream_info] [SOCKOPT_KEY_UPDATE]            [EVENT conn update]
                      [SOCKOPT_CONNECTION_MIGRATION]  [EVENT stream update]
                      [SOCKOPT_STREAM_OPEN/RESET/STOP]
                │ ^               │ ^                     ^
  Userspace     │ │               │ │                     │
  ──────────────│─│───────────────│─│─────────────────────│───────────
  Kernel        │ │               │ │                     │
                v │               v │  ┌──────────────────┘
  ┌──────────────────┬───────────────────────┐
  │ protocol, timer, │ socket (IPPROTO_QUIC) │<──┐{kernel_send/recvmsg()}
  │                  ├───────────────────────┤   │{kernel_set/getsockopt()}
  │ common, family,  │ outqueue  |  inqueue  │   │{kernel_recvmsg()}
  │                  ├───────────────────────┤   │
  │ stream, connid,  │         frame         │   │   ┌─────┐ ┌─────┐
  │                  ├───────────────────────┤   │   │     │ │     │
  │ path, pnspace,   │         packet        │   │───│ SMB │ │ NFS │...
  │                  ├───────────────────────┤   │   │     │ │     │
  │ cong, crypto     │       UDP tunnels     │   │   └─────┘ └─────┘
  └──────────────────┴───────────────────────┘   └──────┴───────┘

Interface
=========

This implementation supports a mapping of QUIC into sockets APIs. Similar
to TCP and SCTP, a typical Server and Client use the following system call
sequence to communicate:

::

    Client                             Server
  ──────────────────────────────────────────────────────────────────────
  sockfd = socket(IPPROTO_QUIC)      listenfd = socket(IPPROTO_QUIC)
  bind(sockfd)                       bind(listenfd)
                                     listen(listenfd)
  connect(sockfd)
  quic_client_handshake(sockfd)
                                     sockfd = accept(listenfd)
                                     quic_server_handshake(sockfd, cert)

  sendmsg(sockfd)                    recvmsg(sockfd)
  close(sockfd)                      close(sockfd)
                                     close(listenfd)

Please note that quic_client_handshake() and quic_server_handshake()
functions are currently sourced from libquic [3]_. These functions are
responsible for receiving and processing the raw TLS handshake messages
until the completion of the handshake process.

For utilization by kernel consumers, it is essential to have tlshd
service [2]_ installed and running in userspace. This service receives
and manages kernel handshake requests for kernel sockets. In the kernel,
the APIs closely resemble those used in userspace:

::

    Client                             Server
  ────────────────────────────────────────────────────────────────────────
  __sock_create(IPPROTO_QUIC, &sock)  __sock_create(IPPROTO_QUIC, &sock)
  kernel_bind(sock)                   kernel_bind(sock)
                                      kernel_listen(sock)
  kernel_connect(sock)
  tls_client_hello_x509(args:{sock})
                                      kernel_accept(sock, &newsock)
                                      tls_server_hello_x509(args:{newsock})

  kernel_sendmsg(sock)                kernel_recvmsg(newsock)
  sock_release(sock)                  sock_release(newsock)
                                      sock_release(sock)

Please be aware that tls_client_hello_x509() and tls_server_hello_x509()
are APIs from net/handshake/. They are used to dispatch the handshake
request to the userspace tlshd service and subsequently block until the
handshake process is completed.

The QUIC module is currently labeled as "EXPERIMENTAL".

.. [1] https://datatracker.ietf.org/doc/html/draft-lxin-quic-socket-apis
.. [2] https://github.com/oracle/ktls-utils
.. [3] https://github.com/lxin/quic
