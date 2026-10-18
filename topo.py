import os
import re
import shutil
import socket
import subprocess
import sys
import time
from argparse import ArgumentParser

from mininet.cli import CLI
from mininet.log import error, setLogLevel
from mininet.net import Mininet
from mininet.node import Switch

H1_IP, H1_GW = "10.0.1.1/24", "10.0.1.254"
H2_IP, H2_GW = "10.0.2.2/24", "10.0.2.254"
H1_MAC = "00:00:0a:00:01:01"
H2_MAC = "00:00:0a:00:02:02"

SWITCHES = {"s1": 1, "s2": 2, "s3": 3, "s4": 4}


def mac_of(sw, port):
    return f"00:aa:00:00:{SWITCHES[sw]:02x}:{port:02x}"


LINKS = [
    ("h1", None, "s1", 1),
    ("s1", 2, "s2", 1),
    ("s1", 3, "s3", 1),
    ("s2", 2, "s4", 1),
    ("s3", 2, "s4", 2),
    ("s4", 3, "h2", None),
]

HOST_CFG = {
    "h1": {"ip": H1_IP, "mac": H1_MAC, "gw": H1_GW, "gw_mac": mac_of("s1", 1)},
    "h2": {"ip": H2_IP, "mac": H2_MAC, "gw": H2_GW, "gw_mac": mac_of("s4", 3)},
}

ROUTES = {
    "s1": [
        ("10.0.2.0/24", 2, mac_of("s2", 1)),
        ("10.0.1.0/24", 1, H1_MAC),
    ],
    "s2": [
        ("10.0.2.0/24", 2, mac_of("s4", 1)),
        ("10.0.1.0/24", 1, mac_of("s1", 2)),
    ],
    "s3": [
        ("10.0.2.0/24", 2, mac_of("s4", 2)),
        ("10.0.1.0/24", 1, mac_of("s1", 3)),
    ],
    "s4": [
        ("10.0.2.0/24", 3, H2_MAC),
        ("10.0.1.0/24", 1, mac_of("s2", 2)),
    ],
}


def thrift_port(sw):
    return 9098 + SWITCHES[sw]


def switch_ports(sw):
    ports = []

    for a, pa, b, pb in LINKS:
        if a == sw and pa:
            ports.append(pa)

        if b == sw and pb:
            ports.append(pb)

    return sorted(ports)


def table_commands(sw):
    cmds = []

    for p in switch_ports(sw):
        cmds.append(
            f"table_add MyEgress.send_frame MyEgress.rewrite_mac {p} => {mac_of(sw, p)}"
        )

    for prefix, port, nh in ROUTES[sw]:
        cmds.append(
            f"table_add MyIngress.ipv4_lpm MyIngress.set_nhop {prefix} => {nh} {port}",
        )

    return cmds


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


class NullSwitch(Switch):
    def start(self, controllers):
        pass

    def stop(self, deleteIntfs=True):
        super().stop(deleteIntfs=deleteIntfs)


class P4Switch(Switch):
    def __init__(
        self,
        name,
        dpid=None,
        opts="",
        listenPort=None,
        json_path=None,
        log_dir="/tmp",
        log_console=False,
        **params,
    ):
        super().__init__(name, dpid, opts, listenPort, **params)
        assert json_path
        if not os.path.isfile(json_path):
            error("Invalid JSON file.\n")
            sys.exit(1)
        self.json_path = json_path
        self.log_dir = log_dir
        self.log_console = log_console

    def start(self, controllers):
        ports = [f"-i {p}@{i.name}" for p, i in sorted(self.intfs.items()) if p != 0]
        n = SWITCHES[self.name]  # pyright: ignore[reportArgumentType]
        # --log-console makes bmv2 print its log (parser, tables, actions...) on stdout,
        # which is redirected to the log file below: follow it with  tail -f /tmp/lb-s1.log
        # --log-flush writes each line immediately instead of in blocks
        log_opts = "--log-console --log-flush" if self.log_console else ""
        cmd = f"simple_switch --device-id {n} --thrift-port {thrift_port(self.name)} {log_opts} {' '.join(ports)} {self.json_path} > {self.log_dir}/lb-{self.name}.log 2>&1 & echo $! > {self.log_dir}/lb-{self.name}.pid"
        print(f"{cmd=}")
        self.cmd(cmd)
        for _ in range(100):
            try:
                socket.create_connection(
                    ("127.0.0.1", thrift_port(self.name)), 0.2
                ).close()
                return
            except OSError:
                time.sleep(0.1)

        sys.exit(
            f"{self.name}: simple_switch did not start, see {self.log_dir}/lb-{self.name}.log"
        )

    def stop(self, deleteIntfs=True):
        self.cmd(f"kill $(cat {self.log_dir}/lb-{self.name}.pid) 2>/dev/null")
        super().stop(deleteIntfs=deleteIntfs)


def prepare_nodes(net):
    for node in net.hosts + net.switches:
        for intf in node.intfs.values():
            if intf.name != "lo":
                node.cmd(f"ethtool -K {intf.name} rx off tx off")

        if node in net.hosts:
            node.cmd("sysctl -q -w net.ipv6.conf.all.disable_ipv6=1")


def load_tables(net):
    for sw in SWITCHES:
        out = run_cli(sw, table_commands(sw))
        # simple_switch_CLI keeps going after a bad command, so show its complaints
        for line in out.splitlines():
            if "rror" in line or "nvalid" in line or "Could not" in line:
                print(f"{sw}: {line.strip()}")


def tx_count(sw, port):
    out = run_cli(sw, [f"counter_read MyEgress.tx_per_port {port}"])
    m = re.search(r"(\d+) packets", out)
    return int(m.group(1)) if m else None


def build(switch_cls=NullSwitch, json=None, log_console=False):
    net = Mininet(controller=None, switch=switch_cls, autoSetMacs=False, build=False)  # pyright: ignore[reportArgumentType]

    for h, cfg in HOST_CFG.items():
        net.addHost(h, ip=cfg["ip"], mac=cfg["mac"])
    for s, id in SWITCHES.items():
        net.addSwitch(s, dpid=f"{id:016x}", json_path=json, log_console=log_console)

    for a, pa, b, pb in LINKS:
        kw = {}

        if pa is not None:
            kw.update(port1=pa, addr1=mac_of(a, pa))
        if pb is not None:
            kw.update(port2=pb, addr2=mac_of(b, pb))

        net.addLink(a, b, **kw)

    return net


def configure_hosts(net):
    for h, cfg in HOST_CFG.items():
        node = net.get(h)
        dev = f"{h}-eth0"

        node.cmd(
            "ip neigh replace {} lladdr {} dev {} nud permanent".format(
                cfg["gw"], cfg["gw_mac"], dev
            )
        )
        node.cmd(
            "ip route add default via {}".format(cfg["gw"]),
        )


def main():
    ap = ArgumentParser()
    ap.add_argument("--json")
    ap.add_argument("--print-commands", action="store_true")
    ap.add_argument(
        "--log-console",
        action="store_true",
        help="start the switches with --log-console (bmv2 log goes to /tmp/lb-<sw>.log)",
    )
    args = ap.parse_args()

    if args.print_commands:
        for sw in SWITCHES:
            print(f"# {sw}  (thrift port {thrift_port(sw)})")
            print("\n".join(table_commands(sw)), "\n")
        return
    if not args.json:
        ap.error("--json is required (compile the P4 file first)")

    setLogLevel("warning")
    net = build(P4Switch, json=args.json, log_console=args.log_console)
    net.start()

    try:
        configure_hosts(net)
        prepare_nodes(net)
        load_tables(net)
        setLogLevel("info")
        CLI(net)
    finally:
        net.stop()


if __name__ == "__main__":
    main()
