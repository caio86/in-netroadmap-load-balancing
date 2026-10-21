from argparse import ArgumentParser


def parse_args():
    ap = ArgumentParser()
    ap.add_argument("--json", help="compiled p4 program")
    ap.add_argument(
        "--print-commands",
        action="store_true",
        help="print table entries of every switch and exit",
    )
    ap.add_argument(
        "--log-console",
        action="store_true",
        help="start the switches with --log-console (bmv2 log goes to /tmp/lb-<sw>.log)",
    )
    return ap, ap.parse_args()


def print_commands():
    from topo.config import SWITCHES, thrift_port
    from topo.tables import table_commands

    for sw in SWITCHES:
        print(f"# {sw} (thrift port {thrift_port(sw)})")
        print("\n".join(table_commands(sw)), "\n")


def main():
    ap, args = parse_args()

    if args.print_commands:
        print_commands()
        return
    if not args.json:
        ap.error("--json is required (compile the P4 file first)")

    from mininet.cli import CLI
    from mininet.log import setLogLevel

    from topo.bmv2 import P4Switch, load_tables, set_queue_limits
    from topo.network import build, configure_hosts, prepare_nodes

    setLogLevel("warning")
    net = build(P4Switch, json=args.json, log_console=args.log_console)  # pyright: ignore[reportArgumentType]
    net.start()

    try:
        configure_hosts(net)
        prepare_nodes(net)
        load_tables()
        set_queue_limits("s1", 2, rate_pps=800, queue_depth=64)
        set_queue_limits("s1", 3, rate_pps=2400, queue_depth=64)
        setLogLevel("info")
        CLI(net)
    finally:
        net.stop()


if __name__ == "__main__":
    main()
