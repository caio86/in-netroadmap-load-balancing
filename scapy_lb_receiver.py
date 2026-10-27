#!/usr/bin/env python3
"""UDP sink with live stdout metrics and interval CSV for Mininet experiments.

Example:
  python3 recv.py --port 9000 --iface h2-eth0 --csv /tmp/receiver_metrics.csv

The receiver prints an aggregate summary every --interval seconds and appends
one CSV row per interval. One-way delay is meaningful when sender and receiver
share a clock (typically true for Mininet hosts on one VM).
"""

import argparse
import csv
import signal
import socket
import struct
import time
from pathlib import Path

PAYLOAD_HEADER = struct.Struct("!IId")
IP_UDP_HEADERS = 28
ETH_HEADER = 14


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument(
        "--interval", type=float, default=2.0, help="stdout/CSV interval in seconds"
    )
    ap.add_argument(
        "--csv", "--log", dest="csv_path", required=True, help="CSV output path"
    )
    ap.add_argument("--rcvbuf", type=int, default=8 * 1024 * 1024)
    args = ap.parse_args()
    if args.interval <= 0:
        ap.error("--interval must be positive")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, args.rcvbuf)
    sock.bind((args.bind, args.port))
    sock.settimeout(0.2)

    stopping = False

    def request_stop(*_):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)

    output = Path(args.csv_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    csv_file = output.open("w", newline="", encoding="utf-8")
    writer = csv.DictWriter(
        csv_file,
        fieldnames=[
            "timestamp",
            "elapsed_s",
            "interval_s",
            "packets",
            "payload_bytes",
            "l3_bytes",
            "l2_estimated_bytes",
            "throughput_l2_mbps",
            "throughput_l3_mbps",
            "packet_rate_pps",
            "mean_delay_ms",
            "max_delay_ms",
            "mean_interarrival_ms",
            "interarrival_jitter_ms",
            "flows_seen",
            "out_of_order_packets",
            "duplicates",
        ],
    )
    writer.writeheader()
    csv_file.flush()

    run_start = time.monotonic()
    interval_start = run_start
    wall_start = time.time()
    next_report = interval_start + args.interval
    total_packets = total_payload = total_l3 = 0
    last_arrival = None
    previous_interarrival = None
    jitter_sum = 0.0
    jitter_count = 0
    interval_packets = interval_payload = interval_l3 = 0
    delay_sum = delay_max = 0.0
    interarrival_sum = 0.0
    interval_arrivals = 0
    interval_ooo = interval_duplicates = 0
    highest = {}
    seen = {}
    flow_set = set()

    print(f"ready: listening on {args.bind}:{args.port}; CSV={output}", flush=True)
    try:
        while not stopping:
            try:
                data, _addr = sock.recvfrom(65535)
            except socket.timeout:
                data = None
            now_mono = time.monotonic()
            now_wall = time.time()

            if data is not None and len(data) >= PAYLOAD_HEADER.size:
                flow, seq, sent_at = PAYLOAD_HEADER.unpack_from(data)
                flow_set.add(flow)
                delay_ms = max(0.0, (now_wall - sent_at) * 1000.0)
                l3_bytes = len(data) + IP_UDP_HEADERS
                interval_packets += 1
                interval_payload += len(data)
                interval_l3 += l3_bytes
                delay_sum += delay_ms
                delay_max = max(delay_max, delay_ms)
                total_packets += 1
                total_payload += len(data)
                total_l3 += l3_bytes

                if last_arrival is not None:
                    interarrival = (now_mono - last_arrival) * 1000.0
                    interarrival_sum += interarrival
                    interval_arrivals += 1
                    if previous_interarrival is not None:
                        jitter_sum += abs(interarrival - previous_interarrival)
                        jitter_count += 1
                    previous_interarrival = interarrival
                last_arrival = now_mono

                if flow not in seen:
                    seen[flow] = set()
                    highest[flow] = -1
                if seq in seen[flow]:
                    interval_duplicates += 1
                else:
                    seen[flow].add(seq)
                    if seq < highest[flow]:
                        interval_ooo += 1
                    highest[flow] = max(highest[flow], seq)

            if now_mono >= next_report:
                actual_interval = max(now_mono - interval_start, 1e-9)
                l2_estimated = interval_l3 + interval_packets * ETH_HEADER
                l2_mbps = l2_estimated * 8 / actual_interval / 1_000_000
                l3_mbps = interval_l3 * 8 / actual_interval / 1_000_000
                pps = interval_packets / actual_interval
                mean_delay = delay_sum / interval_packets if interval_packets else 0.0
                mean_iat = (
                    interarrival_sum / interval_arrivals if interval_arrivals else 0.0
                )
                jitter = jitter_sum / jitter_count if jitter_count else 0.0
                row = {
                    "timestamp": f"{now_wall:.3f}",
                    "elapsed_s": f"{now_mono - run_start:.3f}",
                    "interval_s": f"{actual_interval:.3f}",
                    "packets": interval_packets,
                    "payload_bytes": interval_payload,
                    "l3_bytes": interval_l3,
                    "l2_estimated_bytes": l2_estimated,
                    "throughput_l2_mbps": f"{l2_mbps:.6f}",
                    "throughput_l3_mbps": f"{l3_mbps:.6f}",
                    "packet_rate_pps": f"{pps:.3f}",
                    "mean_delay_ms": f"{mean_delay:.3f}",
                    "max_delay_ms": f"{delay_max:.3f}",
                    "mean_interarrival_ms": f"{mean_iat:.3f}",
                    "interarrival_jitter_ms": f"{jitter:.3f}",
                    "flows_seen": len(flow_set),
                    "out_of_order_packets": interval_ooo,
                    "duplicates": interval_duplicates,
                }
                writer.writerow(row)
                csv_file.flush()
                print(
                    f"{time.strftime('%H:%M:%S')} | "
                    f"{interval_packets:6d} pkts | {pps:8.1f} pps | "
                    f"L3 {l3_mbps:8.3f} Mbit/s | L2* {l2_mbps:8.3f} Mbit/s | "
                    f"flows={len(flow_set)} | delay avg/max={mean_delay:.3f}/{delay_max:.3f} ms",
                    flush=True,
                )
                interval_start = now_mono
                next_report = now_mono + args.interval
                interval_packets = interval_payload = interval_l3 = 0
                delay_sum = delay_max = 0.0
                interarrival_sum = 0.0
                interval_arrivals = 0
                interval_ooo = interval_duplicates = 0
                jitter_sum = 0.0
                jitter_count = 0
    finally:
        sock.close()
        csv_file.close()
        elapsed = max(time.monotonic() - run_start, 1e-9)
        print(
            f"stopped: total_packets={total_packets}, total_payload_bytes={total_payload}, "
            f"avg_rate={total_packets / elapsed:.1f} pps, CSV={output}",
            flush=True,
        )


if __name__ == "__main__":
    main()
