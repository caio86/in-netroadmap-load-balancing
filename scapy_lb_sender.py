#!/usr/bin/env python3
"""Scapy-based paced UDP traffic generator for Mininet/BMv2 experiments.

Example:
  sudo python3 send.py 10.0.2.2 --iface h1-eth0 --dport 9000 \
      --flows 8 --duration 60 --rate 500 --size 512

--rate is the aggregate packet rate across all flows. --size is UDP payload
bytes and must be at least 16 bytes for the measurement header (flow, seq, time).
"""
import argparse
import csv
import random
import signal
import struct
import time
from collections import defaultdict

from scapy.all import Ether, IP, UDP, Raw, conf, get_if_hwaddr

PAYLOAD_HEADER = struct.Struct("!IId")  # flow id, per-flow sequence, Unix send time
ETH_LEN = 14
IP_LEN = 20
UDP_LEN = 8
PAYLOAD_OFFSET = ETH_LEN + IP_LEN + UDP_LEN
PORT_SPAN = 20000


def neighbor_mac(ip):
    """Return a neighbor MAC from the host ARP table."""
    with open("/proc/net/arp", encoding="ascii") as f:
        next(f, None)
        for line in f:
            fields = line.split()
            if len(fields) >= 4 and fields[0] == ip and fields[3] != "00:00:00:00:00:00":
                return fields[3]
    raise SystemExit(
        f"No ARP entry for {ip}. Check connectivity/ARP first, or pass --dst-mac."
    )


def get_source_ports(args):
    if args.seed is None:
        if args.base_port + args.flows - 1 > 65535:
            raise SystemExit("--base-port + --flows - 1 must be <= 65535")
        return [args.base_port + f for f in range(args.flows)]
    if args.flows > PORT_SPAN:
        raise SystemExit(f"--seed supports at most {PORT_SPAN} flows")
    return random.Random(args.seed).sample(
        range(args.base_port, min(args.base_port + PORT_SPAN, 65536)), args.flows
    )


def build_frame(args, iface, dst_mac, sport):
    # Build once; patch only the 16-byte application header on each send.
    frame = (
        Ether(src=get_if_hwaddr(iface), dst=dst_mac)
        / IP(src=args.src_ip, dst=args.dst)
        / UDP(sport=sport, dport=args.dport, chksum=0)
        / Raw(b"\x00" * args.size)
    )
    return bytearray(bytes(frame))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dst", help="destination IP or load-balancer VIP")
    ap.add_argument("--src-ip", help="source IP (default: route-selected source IP)")
    ap.add_argument("--flows", type=int, default=8)
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--packets", type=int, help="packets per flow (default: 10)")
    mode.add_argument("--duration", type=float, help="send for this many seconds")
    ap.add_argument("--rate", type=float, default=500, help="aggregate packets per second")
    ap.add_argument("--size", type=int, default=512, help="UDP payload bytes, including 16-byte measurement header")
    ap.add_argument("--base-port", type=int, default=10000)
    ap.add_argument("--seed", type=int, help="choose reproducible randomized source ports")
    ap.add_argument("--dport", type=int, default=9000)
    ap.add_argument("--iface", help="egress interface (default: interface selected by Scapy route)")
    ap.add_argument("--dst-mac", help="destination next-hop MAC (default: ARP table)")
    ap.add_argument("--log", help="optional per-second/per-flow sender CSV")
    args = ap.parse_args()

    if args.flows < 1 or args.rate <= 0 or args.size < PAYLOAD_HEADER.size:
        ap.error("--flows and --rate must be positive; --size must be at least 16")
    if args.packets is not None and args.packets < 1:
        ap.error("--packets must be positive")
    if args.duration is not None and args.duration <= 0:
        ap.error("--duration must be positive")

    route_iface, src_ip, gateway = conf.route.route(args.dst)
    iface = args.iface or route_iface
    src_ip = args.src_ip or src_ip
    args.src_ip = src_ip
    next_hop = gateway if gateway != "0.0.0.0" else args.dst
    dst_mac = args.dst_mac or neighbor_mac(next_hop)

    ports = get_source_ports(args)
    frames = [build_frame(args, iface, dst_mac, p) for p in ports]
    seq = [0] * args.flows
    sent = defaultdict(lambda: [0, 0])
    sock = conf.L2socket(iface=iface)
    stop = False

    def request_stop(*_):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)

    interval = 1.0 / args.rate
    started = due = time.monotonic()
    sent_total = 0
    print(
        f"Sending to {args.dst}:{args.dport}; iface={iface}; src={src_ip}; "
        f"dst_mac={dst_mac}; flows={args.flows}; target={args.rate:g} pps aggregate; "
        f"payload={args.size} B",
        flush=True,
    )

    try:
        while not stop:
            if args.duration is not None and time.monotonic() - started >= args.duration:
                break
            eligible = [
                f for f in range(args.flows)
                if args.packets is None or seq[f] < args.packets
            ]
            if not eligible:
                break

            # Round-robin through active flows, sending one real Ethernet frame.
            for flow in eligible:
                if stop:
                    break
                if args.duration is not None and time.monotonic() - started >= args.duration:
                    break

                now_wall = time.time()
                PAYLOAD_HEADER.pack_into(frames[flow], PAYLOAD_OFFSET, flow, seq[flow], now_wall)
                try:
                    sock.send(Raw(bytes(frames[flow])))
                except Exception as exc:
                    print(f"send error on flow={flow}, seq={seq[flow]}: {exc}", flush=True)
                    stop = True
                    break

                seq[flow] += 1
                sent_total += 1
                cell = sent[int(now_wall), flow]
                cell[0] += 1
                cell[1] += len(frames[flow]) - ETH_LEN  # IP bytes
                due += interval
                delay = due - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
                else:
                    # Do not burst to catch up; BMv2 queues are often small.
                    due = time.monotonic()
    finally:
        sock.close()

    elapsed = max(time.monotonic() - started, 1e-9)
    print(
        f"Finished: send calls completed={sent_total}; elapsed={elapsed:.2f}s; "
        f"observed rate={sent_total / elapsed:.1f} pps; "
        f"per-flow packets={','.join(str(x) for x in seq)}",
        flush=True,
    )

    if args.log:
        with open(args.log, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["t", "flow", "packets", "ip_bytes"])
            for (t, flow), (packets, nbytes) in sorted(sent.items()):
                writer.writerow([t, flow, packets, nbytes])


if __name__ == "__main__":
    main()
