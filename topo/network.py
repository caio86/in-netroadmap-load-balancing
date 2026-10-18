from mininet.net import Mininet
from mininet.node import Switch

from .config import HOST_CFG, LINKS, SWITCHES, mac_of


class NullSwitch(Switch):
    def start(self, controllers):
        pass


def build(switch_cls=NullSwitch, json=None, log_console=False):
    net = Mininet(controller=None, switch=switch_cls, autoSetMacs=False, build=False)  # pyright: ignore[reportArgumentType]

    for h, cfg in HOST_CFG.items():
        net.addHost(h, ip=cfg["ip"], mac=cfg["mac"])
    for s, number in SWITCHES.items():
        net.addSwitch(s, dpid=f"{number:016x}", json_path=json, log_console=log_console)

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
            f"ip neigh replace {cfg['gw']} lladdr {cfg['gw_mac']} dev {dev} nud permanent"
        )
        node.cmd(f"ip route add default via {cfg['gw']}")


def prepare_nodes(net):
    for node in net.hosts + net.switches:
        for intf in node.intfs.values():
            if intf.name != "lo":
                node.cmd(f"ethtool -K {intf.name} rx off tx off")

        if node in net.hosts:
            node.cmd("sysctl -q -w net.ipv6.conf.all.disable_ipv6=1")
