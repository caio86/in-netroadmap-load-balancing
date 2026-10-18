from .config import H1_MAC, H2_MAC, mac_of, switch_ports

IPV4_LPM = "MyIngress.ipv4_lpm"
SET_NHOP = "MyIngress.set_nhop"
SEND_FRAME = "MyEgress.send_frame"
REWRITE_MAC = "MyEgress.rewrite_mac"
TX_COUNTER = "MyEgress.tx_per_port"

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


def egress_mac_commands(sw):
    return [
        f"table_add {SEND_FRAME} {REWRITE_MAC} {p} => {mac_of(sw, p)}"
        for p in switch_ports(sw)
    ]


def route_commands(sw):
    return [
        f"table_add {IPV4_LPM} {SET_NHOP} {prefix} => {nh} {port}"
        for prefix, port, nh in ROUTES[sw]
    ]


def table_commands(sw):
    return egress_mac_commands(sw) + route_commands(sw)
