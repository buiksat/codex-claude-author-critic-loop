import os
import socket
import subprocess

import pytest

from agent_loop.sandbox import SandboxPolicy, build_bwrap_argv


@pytest.mark.host
def test_008_network_split_for_no_network_role() -> None:
    program = (
        "import os,socket,sys\n"
        "parent_namespace=sys.argv[1];port=int(sys.argv[2])\n"
        "if os.readlink('/proc/self/ns/net') == parent_namespace:\n"
        " raise SystemExit('network namespace was inherited')\n"
        "if [name for _,name in socket.if_nameindex()] != ['lo']:\n"
        " raise SystemExit('private or external interface is present')\n"
        "tcp=socket.socket();tcp.settimeout(.1)\n"
        "try:tcp.connect(('127.0.0.1',port))\n"
        "except OSError:pass\n"
        "else:raise SystemExit('host loopback TCP is reachable')\n"
        "finally:tcp.close()\n"
        "udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n"
        "try:udp.sendto(b'isolated-datagram',('127.0.0.1',port))\n"
        "finally:udp.close()\n"
        "private=socket.socket();private.settimeout(.1)\n"
        "try:private.connect(('10.0.0.1',9))\n"
        "except OSError:pass\n"
        "else:raise SystemExit('private-address TCP is reachable')\n"
        "finally:private.close()\n"
        "try:socket.getaddrinfo('agent-loop-network-boundary.invalid',443)\n"
        "except OSError:pass\n"
        "else:raise SystemExit('DNS unexpectedly resolved')\n"
    )
    parent_namespace = os.readlink("/proc/self/ns/net")
    with (
        socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_listener,
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_listener,
    ):
        tcp_listener.bind(("127.0.0.1", 0))
        port = tcp_listener.getsockname()[1]
        tcp_listener.listen()
        tcp_listener.settimeout(0.05)
        udp_listener.bind(("127.0.0.1", port))
        udp_listener.settimeout(0.05)
        for policy in (SandboxPolicy.validation(), SandboxPolicy.git()):
            result = subprocess.run(
                build_bwrap_argv(
                    policy,
                    (
                        "/usr/bin/python3",
                        "-c",
                        program,
                        parent_namespace,
                        str(port),
                    ),
                ),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                close_fds=True,
                check=False,
                timeout=10,
            )
            assert result.returncode == 0, result.stderr.decode("utf-8", "backslashreplace")
            with pytest.raises(TimeoutError):
                udp_listener.recvfrom(64)
            with pytest.raises(TimeoutError):
                tcp_listener.accept()
