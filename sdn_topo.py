#!/usr/bin/env python3
# sdn_topo.py
from mininet.net import Mininet
from mininet.node import Node, RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info

class LinuxRouter(Node):
    def config(self, **params):
        super(LinuxRouter, self).config(**params)
        self.cmd('sysctl -w net.ipv4.ip_forward=1')
    def terminate(self):
        self.cmd('sysctl -w net.ipv4.ip_forward=0')
        super(LinuxRouter, self).terminate()

def run():
    setLogLevel('info')
    net = Mininet(controller=RemoteController, link=TCLink, switch=OVSSwitch)

    info('*** Adding controller\n')
    c0 = net.addController('c0')  # default to localhost:6653 (works with --network=host)

    info('*** Add routers\n')
    r1 = net.addHost('r1', cls=LinuxRouter)
    r2 = net.addHost('r2', cls=LinuxRouter)
    r3 = net.addHost('r3', cls=LinuxRouter)

    info('*** Add switches\n')
    s1 = net.addSwitch('s1')
    s2 = net.addSwitch('s2')
    s3 = net.addSwitch('s3')

    info('*** Add hosts (2 per switch)\n')
    h1 = net.addHost('h1', ip='10.0.1.10/24')
    h2 = net.addHost('h2', ip='10.0.1.11/24')
    h3 = net.addHost('h3', ip='10.0.2.10/24')
    h4 = net.addHost('h4', ip='10.0.2.11/24')
    h5 = net.addHost('h5', ip='10.0.3.10/24')
    h6 = net.addHost('h6', ip='10.0.3.11/24')

    info('*** Create links (explicit interface names)\n')
    # hosts to switches
    net.addLink(h1, s1, intfName1='h1-eth0', intfName2='s1-eth1')
    net.addLink(h2, s1, intfName1='h2-eth0', intfName2='s1-eth2')
    net.addLink(h3, s2, intfName1='h3-eth0', intfName2='s2-eth1')
    net.addLink(h4, s2, intfName1='h4-eth0', intfName2='s2-eth2')
    net.addLink(h5, s3, intfName1='h5-eth0', intfName2='s3-eth1')
    net.addLink(h6, s3, intfName1='h6-eth0', intfName2='s3-eth2')

    # routers to switches (router-eth0 connects to its switch)
    net.addLink(r1, s1, intfName1='r1-eth0', intfName2='s1-eth3')
    net.addLink(r2, s2, intfName1='r2-eth0', intfName2='s2-eth3')
    net.addLink(r3, s3, intfName1='r3-eth0', intfName2='s3-eth3')

    # router-to-router links (triangle)
    net.addLink(r1, r2, intfName1='r1-eth1', intfName2='r2-eth1')  # r1 <-> r2
    net.addLink(r2, r3, intfName1='r2-eth2', intfName2='r3-eth1')  # r2 <-> r3
    net.addLink(r3, r1, intfName1='r3-eth2', intfName2='r1-eth2')  # r3 <-> r1

    info('*** Starting network\n')
    net.start()

    info('*** Configure IPs on hosts (default gw will be added below)\n')
    h1.cmd('ip addr flush dev h1-eth0; ip addr add 10.0.1.10/24 dev h1-eth0')
    h2.cmd('ip addr flush dev h2-eth0; ip addr add 10.0.1.11/24 dev h2-eth0')
    h3.cmd('ip addr flush dev h3-eth0; ip addr add 10.0.2.10/24 dev h3-eth0')
    h4.cmd('ip addr flush dev h4-eth0; ip addr add 10.0.2.11/24 dev h4-eth0')
    h5.cmd('ip addr flush dev h5-eth0; ip addr add 10.0.3.10/24 dev h5-eth0')
    h6.cmd('ip addr flush dev h6-eth0; ip addr add 10.0.3.11/24 dev h6-eth0')

    info('*** Configure router interfaces (deterministic)\n')
    # r1: r1-eth0 -> s1, r1-eth1 -> r2, r1-eth2 -> r3
    r1.cmd('ifconfig r1-eth0 10.0.1.1/24')
    r1.cmd('ifconfig r1-eth1 192.168.12.1/24')
    r1.cmd('ifconfig r1-eth2 192.168.31.1/24')

    # r2: r2-eth0 -> s2, r2-eth1 -> r1, r2-eth2 -> r3
    r2.cmd('ifconfig r2-eth0 10.0.2.1/24')
    r2.cmd('ifconfig r2-eth1 192.168.12.2/24')
    r2.cmd('ifconfig r2-eth2 192.168.23.1/24')

    # r3: r3-eth0 -> s3, r3-eth1 -> r2, r3-eth2 -> r1
    r3.cmd('ifconfig r3-eth0 10.0.3.1/24')
    r3.cmd('ifconfig r3-eth1 192.168.23.2/24')
    r3.cmd('ifconfig r3-eth2 192.168.31.2/24')

    info('*** Add static routes on routers\n')
    # r1 routes
    r1.cmd('ip route add 10.0.2.0/24 via 192.168.12.2')   # reach network of r2
    r1.cmd('ip route add 10.0.3.0/24 via 192.168.31.2')   # reach network of r3

    # r2 routes
    r2.cmd('ip route add 10.0.1.0/24 via 192.168.12.1')
    r2.cmd('ip route add 10.0.3.0/24 via 192.168.23.2')

    # r3 routes
    r3.cmd('ip route add 10.0.1.0/24 via 192.168.31.1')
    r3.cmd('ip route add 10.0.2.0/24 via 192.168.23.1')

    info('*** Configure default gateway on hosts\n')
    h1.cmd('ip route add default via 10.0.1.1')
    h2.cmd('ip route add default via 10.0.1.1')
    h3.cmd('ip route add default via 10.0.2.1')
    h4.cmd('ip route add default via 10.0.2.1')
    h5.cmd('ip route add default via 10.0.3.1')
    h6.cmd('ip route add default via 10.0.3.1')
    

    info('*** Dropping to CLI\n')
    CLI(net)
    net.stop()

if __name__ == "__main__":
    run()