from .config import H1_MAC, H2_MAC, mac_of, switch_ports

IPV4_LPM = "MyIngress.ipv4_lpm"
SET_NHOP = "MyIngress.set_nhop"
SET_LB_GROUP = "MyIngress.set_lb_group"
LB_NHOP = "MyIngress.lb_nhop"
LB_THRESHOLD = "MyIngress.lb_threshold"
BUCKET_COUNTER = "MyIngress.bucket_pkts"
SEND_FRAME = "MyEgress.send_frame"
REWRITE_MAC = "MyEgress.rewrite_mac"
TX_COUNTER = "MyEgress.tx_per_port"

LB_GROUPS = {
    "s1": [
        {
            "prefix": "10.0.2.0/24",
            "n_buckets": 32,
            "initial_threshold": 16,
            "links": [
                (2, mac_of("s2", 1)),
                (3, mac_of("s3", 1)),
            ],
        },
    ]
}

ROUTES = {
    "s1": [
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


def lb_commands(sw):
    if sw not in LB_GROUPS:
        return []

    cfg = LB_GROUPS[sw]
    cmds = []
    for group_cfg in cfg:
        prefix = group_cfg["prefix"]
        n_buckets = group_cfg["n_buckets"]
        initial_threshold = group_cfg["initial_threshold"]
        links = group_cfg["links"]

        cmds.append(f"table_add {IPV4_LPM} {SET_LB_GROUP} {prefix} => {n_buckets}")

        for link, (port, nhop_mac) in enumerate(links):
            cmds.append(f"table_add {LB_NHOP} {SET_NHOP} {link} => {nhop_mac} {port}")

        cmds.append(f"register_write {LB_THRESHOLD} 0 {initial_threshold}")
    return cmds


def table_commands(sw):
    return route_commands(sw) + lb_commands(sw) + egress_mac_commands(sw)
