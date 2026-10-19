import os
import re
import shutil
import socket
import subprocess
import sys
import time

from mininet.log import error, info
from mininet.node import Switch

from .config import SWITCHES, thrift_port
from .tables import LB_THRESHOLD, table_commands


def cli_exe():
    for name in ("simple_switch_CLI", "runtime_CLI"):
        if shutil.which(name):
            return name
    sys.exit("simple_switch_CLI not found on PATH (it comes with bmv2)")


def run_cli(sw, commands):
    p = subprocess.run(
        [cli_exe(), "--thrift-port", str(thrift_port(sw))],
        check=False,
        input="\n".join(commands) + "\n",
        capture_output=True,
        text=True,
    )
    return p.stdout


def load_tables(net):
    for sw in SWITCHES:
        out = run_cli(sw, table_commands(sw))
        # simple_switch_CLI keeps going after a bad command, so show its complaints
        for line in out.splitlines():
            if "rror" in line or "nvalid" in line or "Could not" in line:
                print(f"{sw}: {line.strip()}")


def read_counter(sw, counter, index):
    out = run_cli(sw, [f"counter_read {counter} {index}"])
    m = re.search(r"(\d+) packets", out)
    return int(m.group(1)) if m else None


def read_counters(sw, counter, n):
    out = run_cli(sw, [f"counter_read {counter} {i}" for i in range(n)])
    cells = {
        int(i): int(pkts)
        for i, pkts in re.findall(r"\[(\d+)\]= \(\d+ bytes, (\d+) packets\)", out)
    }
    return [cells[i] for i in range(n)]


def set_threshold(sw, value):
    run_cli(sw, [f"register_write {LB_THRESHOLD} 0 {value}"])


def reset_counter(sw, counter):
    run_cli(sw, [f"counter_reset {counter}"])


class P4Switch(Switch):
    def __init__(
        self,
        name: str,
        dpid=None,
        opts="",
        listenPort=None,
        json_path: str | None = None,
        log_dir="/tmp",
        log_console=False,
        **params,
    ):
        super().__init__(name, dpid, opts, listenPort, **params)
        if not json_path or not os.path.isfile(json_path):
            error("Invalid JSON file.\n")
            sys.exit(1)
        self.json_path = json_path
        self.log_dir = log_dir
        self.log_console = log_console

    @property
    def log_file(self):
        return f"{self.log_dir}/lb-{self.name}.log"

    @property
    def pid_file(self):
        return f"{self.log_dir}/lb-{self.name}.pid"

    def start(self, controllers):
        ports = " ".join(
            f"-i {p}@{i.name}" for p, i in sorted(self.intfs.items()) if p != 0
        )
        # --log-console makes bmv2 print its log (parser, tables, actions...) on stdout,
        # which is redirected to the log file below: follow it with  tail -f /tmp/lb-s1.log
        # --log-flush writes each line immediately instead of in blocks
        log_opts = "--log-console --log-flush" if self.log_console else ""
        cmd = (
            f"simple_switch --device-id {SWITCHES[self.name]} "  # pyright: ignore[reportArgumentType]
            f"--thrift-port {thrift_port(self.name)} {log_opts} {ports} {self.json_path} "
            f"> {self.log_file} 2>&1 & echo $! > {self.pid_file}"
        )
        info(f"Starting switch cmd: {cmd=}")
        self.cmd(cmd)
        self._wait_for_thrift()

    def _wait_for_thrift(self):
        for _ in range(100):
            try:
                socket.create_connection(
                    ("127.0.0.1", thrift_port(self.name)), 0.2
                ).close()
                return
            except OSError:
                time.sleep(0.1)

        sys.exit(f"{self.name}: simple_switch did not start, see {self.log_file}")

    def stop(self, deleteIntfs=True):
        self.cmd(f"kill $(cat {self.pid_file}) 2>/dev/null")
        super().stop(deleteIntfs=deleteIntfs)
