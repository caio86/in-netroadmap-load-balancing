#!/usr/bin/env python3
"""UDP sink with live stdout metrics, interval CSV, and a Prometheus /metrics endpoint.

Example (run inside a Mininet host):
  python3 scapy_lb_receiver.py --port 9000 --csv /tmp/receiver_metrics.csv \
      --prometheus-bind 0.0.0.0 --prometheus-port 9108

The receiver prints and writes one interval summary every --interval seconds.
Prometheus scrapes the HTTP endpoint independently; configure its scrape_interval
in prometheus.yml to control how often samples are collected.
"""
import argparse
import csv
import signal
import socket
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PAYLOAD_HEADER = struct.Struct("!IId")  # flow id, per-flow sequence, Unix send timestamp
IP_UDP_HEADERS = 28
ETH_HEADER = 14

# metric-name -> (type, help, state key)
METRICS = {
    "network_receiver_up": ("gauge", "Whether the receiver process is running.", "up"),
    "network_receiver_packets_received_total": ("counter", "Total UDP packets received with a valid measurement header.", "total_packets"),
    "network_receiver_payload_bytes_received_total": ("counter", "Total UDP payload bytes received.", "total_payload_bytes"),
    "network_receiver_l3_bytes_received_total": ("counter", "Total estimated IPv4 packet bytes received.", "total_l3_bytes"),
    "network_receiver_out_of_order_packets_total": ("counter", "Total out-of-order packets observed.", "total_out_of_order"),
    "network_receiver_duplicates_total": ("counter", "Total duplicate packets observed.", "total_duplicates"),
    "network_receiver_intervals_total": ("counter", "Number of reporting intervals completed.", "intervals_total"),
    "network_receiver_interval_packets": ("gauge", "Packets received during the latest reporting interval.", "interval_packets"),
    "network_receiver_interval_payload_bytes": ("gauge", "UDP payload bytes received during the latest interval.", "interval_payload_bytes"),
    "network_receiver_interval_l3_bytes": ("gauge", "Estimated IPv4 packet bytes during the latest interval.", "interval_l3_bytes"),
    "network_receiver_throughput_l2_mbps": ("gauge", "Estimated Ethernet frame throughput in decimal megabits per second; excludes FCS, preamble and inter-frame gap.", "throughput_l2_mbps"),
    "network_receiver_throughput_l3_mbps": ("gauge", "Estimated IPv4 packet throughput in decimal megabits per second.", "throughput_l3_mbps"),
    "network_receiver_packet_rate_pps": ("gauge", "Packets received per second in the latest reporting interval.", "packet_rate_pps"),
    "network_receiver_mean_delay_ms": ("gauge", "Mean one-way delay estimated from sender timestamps in milliseconds.", "mean_delay_ms"),
    "network_receiver_max_delay_ms": ("gauge", "Maximum one-way delay observed in the latest interval in milliseconds.", "max_delay_ms"),
    "network_receiver_mean_interarrival_ms": ("gauge", "Mean packet inter-arrival interval in milliseconds.", "mean_interarrival_ms"),
    "network_receiver_interarrival_jitter_ms": ("gauge", "Mean absolute change between consecutive inter-arrival intervals in milliseconds.", "interarrival_jitter_ms"),
    "network_receiver_flows_seen": ("gauge", "Distinct flow identifiers observed since receiver start.", "flows_seen"),
    "network_receiver_interval_out_of_order_packets": ("gauge", "Out-of-order packets observed in the latest interval.", "interval_out_of_order"),
    "network_receiver_interval_duplicates": ("gauge", "Duplicate packets observed in the latest interval.", "interval_duplicates"),
    "network_receiver_last_interval_timestamp_seconds": ("gauge", "Unix timestamp at the end of the latest reporting interval.", "last_interval_timestamp"),
}


def prom_escape(value):
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


class MetricsState:
    def __init__(self, receiver, udp_port):
        self.labels = {"receiver": receiver, "udp_port": str(udp_port)}
        self.lock = threading.Lock()
        self.values = {key: 0 for _, _, key in METRICS.values()}
        self.values["up"] = 1

    def update(self, values):
        with self.lock:
            self.values.update(values)

    def exposition(self):
        with self.lock:
            snapshot = dict(self.values)
        label_text = "{" + ",".join(
            f'{name}="{prom_escape(value)}"' for name, value in sorted(self.labels.items())
        ) + "}"
        lines = []
        for metric_name, (metric_type, help_text, state_key) in METRICS.items():
            lines.append(f"# HELP {metric_name} {help_text}")
            lines.append(f"# TYPE {metric_name} {metric_type}")
            value = snapshot.get(state_key, 0)
            if isinstance(value, float):
                rendered = f"{value:.12g}"
            else:
                rendered = str(value)
            lines.append(f"{metric_name}{label_text} {rendered}")
        return "\n".join(lines) + "\n"


class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/metrics":
            self.send_error(404, "Use /metrics")
            return
        body = self.server.metrics_state.exposition().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        # Avoid an HTTP access log line on every Prometheus scrape.
        return


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=9000, help="UDP destination port")
    ap.add_argument("--bind", default="0.0.0.0", help="UDP bind address")
    ap.add_argument("--interval", type=float, default=2.0, help="stdout/CSV reporting interval in seconds")
    ap.add_argument("--csv", "--log", dest="csv_path", required=True, help="CSV output path")
    ap.add_argument("--rcvbuf", type=int, default=8 * 1024 * 1024, help="UDP receive buffer size")
    ap.add_argument("--prometheus-bind", default="0.0.0.0", help="HTTP bind address for /metrics")
    ap.add_argument("--prometheus-port", type=int, default=9108, help="HTTP port for /metrics (default: 9108)")
    ap.add_argument("--prometheus-receiver", default="h2", help="receiver label value exposed to Prometheus")
    args = ap.parse_args()

    if args.interval <= 0:
        ap.error("--interval must be positive")
    if not 1 <= args.port <= 65535:
        ap.error("--port must be in 1..65535")
    if not 1 <= args.prometheus_port <= 65535:
        ap.error("--prometheus-port must be in 1..65535")

    # Bind the metrics endpoint before starting the data-plane receiver. If the
    # port is unavailable, fail clearly instead of silently running unmonitored.
    metrics_state = MetricsState(args.prometheus_receiver, args.port)
    http_server = ThreadingHTTPServer((args.prometheus_bind, args.prometheus_port), MetricsHandler)
    http_server.daemon_threads = True
    http_server.metrics_state = metrics_state
    http_thread = threading.Thread(target=http_server.serve_forever, name="prometheus-metrics", daemon=True)
    http_thread.start()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, args.rcvbuf)
    try:
        sock.bind((args.bind, args.port))
    except Exception:
        http_server.shutdown()
        http_server.server_close()
        sock.close()
        raise
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
    fields = [
        "timestamp", "elapsed_s", "interval_s", "packets", "payload_bytes",
        "l3_bytes", "l2_estimated_bytes", "throughput_l2_mbps",
        "throughput_l3_mbps", "packet_rate_pps", "mean_delay_ms",
        "max_delay_ms", "mean_interarrival_ms", "interarrival_jitter_ms",
        "flows_seen", "out_of_order_packets", "duplicates",
    ]
    writer = csv.DictWriter(csv_file, fieldnames=fields)
    writer.writeheader()
    csv_file.flush()

    run_start = time.monotonic()
    interval_start = run_start
    next_report = interval_start + args.interval
    total_packets = total_payload = total_l3 = 0
    total_out_of_order = total_duplicates = 0
    last_arrival = None
    previous_interarrival = None
    interval_packets = interval_payload = interval_l3 = 0
    delay_sum = delay_max = 0.0
    interarrival_sum = 0.0
    interval_arrivals = 0
    interval_ooo = interval_duplicates = 0
    jitter_sum = 0.0
    jitter_count = 0
    highest = {}
    seen = {}
    flow_set = set()
    intervals_total = 0

    print(f"ready: UDP listening on {args.bind}:{args.port}; CSV={output}", flush=True)
    print(
        f"prometheus: http://{args.prometheus_bind}:{args.prometheus_port}/metrics "
        f"(receiver={args.prometheus_receiver})",
        flush=True,
    )
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
                    total_duplicates += 1
                else:
                    seen[flow].add(seq)
                    if seq < highest[flow]:
                        interval_ooo += 1
                        total_out_of_order += 1
                    highest[flow] = max(highest[flow], seq)

            if now_mono >= next_report:
                actual_interval = max(now_mono - interval_start, 1e-9)
                l2_estimated = interval_l3 + interval_packets * ETH_HEADER
                l2_mbps = l2_estimated * 8 / actual_interval / 1_000_000
                l3_mbps = interval_l3 * 8 / actual_interval / 1_000_000
                pps = interval_packets / actual_interval
                mean_delay = delay_sum / interval_packets if interval_packets else 0.0
                mean_iat = interarrival_sum / interval_arrivals if interval_arrivals else 0.0
                jitter = jitter_sum / jitter_count if jitter_count else 0.0
                row = {
                    "timestamp": f"{now_wall:.6f}",
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
                intervals_total += 1

                metrics_state.update({
                    "up": 1,
                    "total_packets": total_packets,
                    "total_payload_bytes": total_payload,
                    "total_l3_bytes": total_l3,
                    "total_out_of_order": total_out_of_order,
                    "total_duplicates": total_duplicates,
                    "intervals_total": intervals_total,
                    "interval_packets": interval_packets,
                    "interval_payload_bytes": interval_payload,
                    "interval_l3_bytes": interval_l3,
                    "throughput_l2_mbps": l2_mbps,
                    "throughput_l3_mbps": l3_mbps,
                    "packet_rate_pps": pps,
                    "mean_delay_ms": mean_delay,
                    "max_delay_ms": delay_max,
                    "mean_interarrival_ms": mean_iat,
                    "interarrival_jitter_ms": jitter,
                    "flows_seen": len(flow_set),
                    "interval_out_of_order": interval_ooo,
                    "interval_duplicates": interval_duplicates,
                    "last_interval_timestamp": now_wall,
                })

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
        metrics_state.update({"up": 0})
        sock.close()
        csv_file.close()
        http_server.shutdown()
        http_server.server_close()
        elapsed = max(time.monotonic() - run_start, 1e-9)
        print(
            f"stopped: total_packets={total_packets}, total_payload_bytes={total_payload}, "
            f"avg_rate={total_packets / elapsed:.1f} pps, CSV={output}",
            flush=True,
        )


if __name__ == "__main__":
    main()
