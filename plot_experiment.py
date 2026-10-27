#!/usr/bin/env python3
"""Plot switch/Q-learning metrics from s1.csv and traffic metrics from recv.csv.

Dependencies:
    python -m pip install pandas matplotlib

Typical usage (with s1.csv and recv.csv in the current directory):
    python plot_experiment.py

Custom paths/output directory:
    python plot_experiment.py --s1 path/to/s1.csv --recv path/to/recv.csv --outdir plots

The script writes PNG figures and a short run summary to the output directory.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Iterable

import matplotlib
matplotlib.use("Agg")  # Works on headless experiment VMs.
import matplotlib.pyplot as plt
import pandas as pd


SWITCH_TIME = "t"
RECEIVER_TIME = "timestamp"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Plot switch/Q-learning and receiver metrics from two CSV files."
    )
    parser.add_argument("--s1", type=Path, default=Path("s1.csv"),
                        help="Switch/Q-learning CSV (default: s1.csv)")
    parser.add_argument("--recv", type=Path, default=Path("recv.csv"),
                        help="Receiver metrics CSV (default: recv.csv)")
    parser.add_argument("--outdir", type=Path, default=Path("plots"),
                        help="Directory for generated PNG files (default: plots/)")
    parser.add_argument("--show", action="store_true",
                        help="Open plot windows after saving (requires a graphical session).")
    return parser.parse_args()


def load_csv(path: Path, time_column: str, label: str) -> pd.DataFrame:
    if not path.is_file():
        raise FileNotFoundError(f"{label} CSV was not found: {path}")

    df = pd.read_csv(path)
    if df.empty:
        raise ValueError(f"{label} CSV has a header but no data rows: {path}")
    if time_column not in df.columns:
        raise ValueError(
            f"{label} CSV must contain a '{time_column}' column. "
            f"Found columns: {', '.join(map(str, df.columns))}"
        )

    # Coerce metric cells to numeric; non-numeric/empty cells become NaN.
    for column in df.columns:
        df[column] = pd.to_numeric(df[column], errors="coerce")

    df = df.dropna(subset=[time_column]).sort_values(time_column).reset_index(drop=True)
    if df.empty:
        raise ValueError(f"No valid timestamps in {label} CSV: {path}")
    return df


def add_relative_time(
    df: pd.DataFrame, timestamp_column: str, experiment_start: float
) -> pd.DataFrame:
    result = df.copy()
    result["time_s"] = result[timestamp_column] - experiment_start
    return result


def present(df: pd.DataFrame, columns: Iterable[str]) -> list[str]:
    return [column for column in columns if column in df.columns and df[column].notna().any()]


def style_axis(ax: plt.Axes, title: str, ylabel: str) -> None:
    ax.set_title(title)
    ax.set_xlabel("Time since first switch sample (s)")
    ax.set_ylabel(ylabel)
    ax.grid(True, alpha=0.3)


def save_figure(fig: plt.Figure, outdir: Path, filename: str) -> None:
    fig.tight_layout()
    fig.savefig(outdir / filename, dpi=160, bbox_inches="tight")


def plot_lines(
    df: pd.DataFrame,
    x: str,
    columns: list[str],
    labels: dict[str, str],
    title: str,
    ylabel: str,
    outdir: Path,
    filename: str,
    *,
    step: bool = False,
    show: bool = False,
) -> bool:
    columns = present(df, columns)
    if not columns:
        return False

    fig, ax = plt.subplots(figsize=(10, 5.5))
    for column in columns:
        label = labels.get(column, column)
        if step:
            ax.step(df[x], df[column], where="post", label=label)
        else:
            ax.plot(df[x], df[column], marker="o", markersize=3, label=label)
    style_axis(ax, title, ylabel)
    if len(columns) > 1:
        ax.legend(loc="best")
    save_figure(fig, outdir, filename)
    if show:
        plt.show(block=False)
    plt.close(fig)
    return True


def plot_receiver_grouped_metrics(
    recv: pd.DataFrame, outdir: Path, show: bool
) -> list[str]:
    created: list[str] = []
    specs = [
        (
            ["throughput_l2_mbps", "throughput_l3_mbps"],
            {"throughput_l2_mbps": "L2 throughput", "throughput_l3_mbps": "L3 throughput"},
            "Receiver throughput", "Throughput (Mbps)", "receiver_throughput.png",
        ),
        (
            ["packet_rate_pps"], {"packet_rate_pps": "Packet rate"},
            "Receiver packet rate", "Packets per second (pps)", "receiver_packet_rate.png",
        ),
        (
            ["mean_delay_ms", "max_delay_ms"],
            {"mean_delay_ms": "Mean delay", "max_delay_ms": "Maximum delay"},
            "Receiver packet delay", "Delay (ms)", "receiver_latency.png",
        ),
        (
            ["mean_interarrival_ms", "interarrival_jitter_ms"],
            {"mean_interarrival_ms": "Mean inter-arrival", "interarrival_jitter_ms": "Inter-arrival jitter"},
            "Packet inter-arrival timing", "Time (ms)", "receiver_interarrival.png",
        ),
        (
            ["flows_seen"], {"flows_seen": "Flows seen"},
            "Flows observed by receiver", "Flows", "receiver_flows.png",
        ),
        (
            ["out_of_order_packets", "duplicates"],
            {"out_of_order_packets": "Out-of-order packets", "duplicates": "Duplicate packets"},
            "Receiver packet anomalies", "Packets per interval", "receiver_packet_anomalies.png",
        ),
    ]
    for columns, labels, title, ylabel, filename in specs:
        if plot_lines(recv, "time_s", columns, labels, title, ylabel,
                      outdir, filename, show=show):
            created.append(filename)

    # Packet count and byte counters use their own graph because their scales differ.
    for columns, labels, title, ylabel, filename in [
        (["packets"], {"packets": "Packets received"},
         "Packets received per interval", "Packets", "receiver_packets.png"),
        (["payload_bytes", "l3_bytes", "l2_estimated_bytes"],
         {"payload_bytes": "Payload bytes", "l3_bytes": "L3 bytes", "l2_estimated_bytes": "Estimated L2 bytes"},
         "Receiver byte counts per interval", "Bytes", "receiver_bytes.png"),
    ]:
        if plot_lines(recv, "time_s", columns, labels, title, ylabel,
                      outdir, filename, show=show):
            created.append(filename)
    return created


def plot_switch_metrics(switch: pd.DataFrame, outdir: Path, show: bool) -> list[str]:
    created: list[str] = []
    specs = [
        (["w0", "w1", "w2", "w3"],
         {"w0": "Weight 0", "w1": "Weight 1", "w2": "Weight 2", "w3": "Weight 3"},
         "Q-learning / load-balancing weights", "Weight", "switch_weights.png", False),
        (["link0_pkts", "link1_pkts", "link2_pkts", "link3_pkts"],
         {f"link{i}_pkts": f"Link {i}" for i in range(4)},
         "Packets per link", "Packets", "switch_link_packets.png", False),
        (["tx_port1", "tx_port2", "tx_port3"],
         {"tx_port1": "TX port 1", "tx_port2": "TX port 2", "tx_port3": "TX port 3"},
         "Transmitted packets per port", "Packets", "switch_tx_ports.png", False),
        (["state"], {"state": "State"},
         "Q-learning state", "State", "qlearning_state.png", True),
        (["cost"], {"cost": "Cost"},
         "Q-learning cost", "Cost", "qlearning_cost.png", False),
        (["action"], {"action": "Action"},
         "Q-learning action", "Action", "qlearning_action.png", True),
        (["iteration"], {"iteration": "Iteration"},
         "Q-learning iteration", "Iteration", "qlearning_iteration.png", False),
    ]
    for spec in specs:
        # Keep specs simple to read while supporting a step chart for discrete state/action values.
        if len(spec) == 6:
            columns, labels, title, ylabel, filename, use_step = spec
        else:
            columns, labels, title, ylabel, filename = spec
            use_step = False
        if plot_lines(switch, "time_s", columns, labels, title, ylabel,
                      outdir, filename, step=use_step, show=show):
            created.append(filename)
    return created


def plot_overview(switch: pd.DataFrame, recv: pd.DataFrame, outdir: Path, show: bool) -> bool:
    """Make a single overview figure using a shared time origin for both CSVs."""
    fig, axes = plt.subplots(3, 1, figsize=(11, 10), sharex=True)
    any_data = False

    weight_cols = present(switch, ["w0", "w1", "w2", "w3"])
    if weight_cols:
        any_data = True
        for col in weight_cols:
            axes[0].plot(switch["time_s"], switch[col], marker="o", markersize=3, label=col)
        axes[0].set_title("Switch weights")
        axes[0].set_ylabel("Weight")
        axes[0].legend(loc="best")
        axes[0].grid(True, alpha=0.3)
    else:
        axes[0].set_visible(False)

    throughput_cols = present(recv, ["throughput_l2_mbps", "throughput_l3_mbps"])
    if throughput_cols:
        any_data = True
        labels = {"throughput_l2_mbps": "L2 throughput", "throughput_l3_mbps": "L3 throughput"}
        for col in throughput_cols:
            axes[1].plot(recv["time_s"], recv[col], marker="o", markersize=3, label=labels[col])
        axes[1].set_title("Receiver throughput")
        axes[1].set_ylabel("Mbps")
        axes[1].legend(loc="best")
        axes[1].grid(True, alpha=0.3)
    else:
        axes[1].set_visible(False)

    latency_cols = present(recv, ["mean_delay_ms", "max_delay_ms"])
    if latency_cols:
        any_data = True
        labels = {"mean_delay_ms": "Mean delay", "max_delay_ms": "Maximum delay"}
        for col in latency_cols:
            axes[2].plot(recv["time_s"], recv[col], marker="o", markersize=3, label=labels[col])
        axes[2].set_title("Receiver packet delay")
        axes[2].set_ylabel("ms")
        axes[2].legend(loc="best")
        axes[2].grid(True, alpha=0.3)
    else:
        axes[2].set_visible(False)

    axes[2].set_xlabel("Seconds since first switch sample")
    if not any_data:
        plt.close(fig)
        return False
    save_figure(fig, outdir, "experiment_overview.png")
    if show:
        plt.show(block=False)
    plt.close(fig)
    return True


def main() -> int:
    args = parse_args()
    try:
        switch = load_csv(args.s1, SWITCH_TIME, "Switch/Q-learning")
        recv = load_csv(args.recv, RECEIVER_TIME, "Receiver")
        # A common time origin makes it possible to compare both traces in the overview.
        experiment_start = min(float(switch[SWITCH_TIME].min()), float(recv[RECEIVER_TIME].min()))
        switch = add_relative_time(switch, SWITCH_TIME, experiment_start)
        recv = add_relative_time(recv, RECEIVER_TIME, experiment_start)

        args.outdir.mkdir(parents=True, exist_ok=True)
        generated = plot_switch_metrics(switch, args.outdir, args.show)
        generated.extend(plot_receiver_grouped_metrics(recv, args.outdir, args.show))
        if plot_overview(switch, recv, args.outdir, args.show):
            generated.append("experiment_overview.png")

        summary = [
            "Experiment plot summary",
            "=======================",
            f"Switch file:   {args.s1} ({len(switch)} rows)",
            f"Receiver file: {args.recv} ({len(recv)} rows)",
            f"Time origin:   Unix timestamp {experiment_start:.3f}",
            f"Figures saved: {len(generated)}",
            *[f"  - {name}" for name in generated],
        ]
        summary_path = args.outdir / "plot_summary.txt"
        summary_path.write_text("\n".join(summary) + "\n", encoding="utf-8")
        print("\n".join(summary))
        print(f"\nOutput directory: {args.outdir.resolve()}")
        if not generated:
            print("Warning: no recognized metric columns were found to plot.", file=sys.stderr)
        return 0
    except (FileNotFoundError, ValueError, pd.errors.ParserError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
