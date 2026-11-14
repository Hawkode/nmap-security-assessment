#!/usr/bin/env python3
"""Minimal TCP connect scanner, standard library only.

Shows what Nmap's -sT scan does underneath: a full TCP handshake per port.
It is slower and louder than Nmap's default SYN scan (every open port is a
completed connection the target can log). Scan only hosts you are authorised
to test.

Usage:
    python3 tcp_connect_scan.py 192.168.56.101 -p 1-1024
    python3 tcp_connect_scan.py scanme.nmap.org -p 22,80,443 --timeout 0.5
"""

from __future__ import annotations

import argparse
import socket
import sys
from concurrent.futures import ThreadPoolExecutor


def parse_ports(spec: str) -> list[int]:
    """Parse '22,80,8000-8010' into a sorted list of unique ports."""
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start, end = int(start_s), int(end_s)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    bad = [p for p in ports if not 1 <= p <= 65535]
    if bad:
        raise ValueError(f"ports out of range 1-65535: {bad[:5]}")
    return sorted(ports)


def check_port(host: str, port: int, timeout: float) -> tuple[int, bool]:
    """Return (port, open). Open means the TCP handshake completed."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return port, sock.connect_ex((host, port)) == 0


def service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Minimal TCP connect scanner.")
    parser.add_argument("host", help="target host name or IPv4 address")
    parser.add_argument("-p", "--ports", default="1-1024", help="e.g. 22,80,443 or 1-1024 (default)")
    parser.add_argument("--timeout", type=float, default=1.0, help="seconds per port (default 1.0)")
    parser.add_argument("--workers", type=int, default=100, help="parallel connections (default 100)")
    args = parser.parse_args(argv)

    try:
        ports = parse_ports(args.ports)
        target = socket.gethostbyname(args.host)
    except (ValueError, socket.gaierror) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"Scanning {args.host} ({target}), {len(ports)} TCP ports")
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        results = pool.map(lambda p: check_port(target, p, args.timeout), ports)
        open_ports = [port for port, is_open in results if is_open]

    for port in open_ports:
        print(f"{port}/tcp open  {service_name(port)}")
    print(f"{len(open_ports)} open, {len(ports) - len(open_ports)} closed or filtered")
    return 0


if __name__ == "__main__":
    sys.exit(main())
