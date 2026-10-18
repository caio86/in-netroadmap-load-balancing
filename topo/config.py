# HOSTS

H1_IP, H1_GW = "10.0.1.1/24", "10.0.1.254"
H2_IP, H2_GW = "10.0.2.2/24", "10.0.2.254"
H1_MAC = "00:00:0a:00:01:01"
H2_MAC = "00:00:0a:00:02:02"

# SWITCHES

SWITCHES = {"s1": 1, "s2": 2, "s3": 3, "s4": 4}


def mac_of(sw, port):
    return f"00:aa:00:00:{SWITCHES[sw]:02x}:{port:02x}"


def thrift_port(sw):
    return 9098 + SWITCHES[sw]


# LINKS

LINKS = [
    ("h1", None, "s1", 1),
    ("s1", 2, "s2", 1),
    ("s1", 3, "s3", 1),
    ("s2", 2, "s4", 1),
    ("s3", 2, "s4", 2),
    ("s4", 3, "h2", None),
]


def switch_ports(sw):
    ports = []

    for a, pa, b, pb in LINKS:
        if a == sw and pa:
            ports.append(pa)

        if b == sw and pb:
            ports.append(pb)

    return sorted(ports)


# HOST CONFIGURATION

HOST_CFG = {
    "h1": {"ip": H1_IP, "mac": H1_MAC, "gw": H1_GW, "gw_mac": mac_of("s1", 1)},
    "h2": {"ip": H2_IP, "mac": H2_MAC, "gw": H2_GW, "gw_mac": mac_of("s4", 3)},
}
