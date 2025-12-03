#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.node import Node, RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from time import sleep

from datetime import datetime
from random import randrange, choice

# Define the Router class according to sdn_topo.py
class LinuxRouter(Node):
    def config(self, **params):
        super(LinuxRouter, self).config(**params)
        self.cmd('sysctl -w net.ipv4.ip_forward=1')
    def terminate(self):
        self.cmd('sysctl -w net.ipv4.ip_forward=0')
        super(LinuxRouter, self).terminate()

# Only generate IPs within the host range (h1-h6: 10.0.1.10, 10.0.1.11, 10.0.2.10, 10.0.2.11, 10.0.3.10, 10.0.3.11)
def ip_generator():
    # Randomly select an IP from the 6 hosts range
    ips = [
        "10.0.1.10", "10.0.1.11",
        "10.0.2.10", "10.0.2.11",
        "10.0.3.10", "10.0.3.11",
    ]
    return choice(ips)

def startNetwork():
    # Initialize and configure the network according to sdn_topo.py
    setLogLevel('info')
    net = Mininet(controller=RemoteController, link=TCLink, switch=OVSSwitch)

    info('*** Adding controller\n')
    c0 = net.addController('c0')

    info('*** Add nodes (routers, switches, hosts)\n')
    r1 = net.addHost('r1', cls=LinuxRouter)
    r2 = net.addHost('r2', cls=LinuxRouter)
    r3 = net.addHost('r3', cls=LinuxRouter)

    s1 = net.addSwitch('s1')
    s2 = net.addSwitch('s2')
    s3 = net.addSwitch('s3')

    # Hosts with IPs according to sdn_topo.py
    h1 = net.addHost('h1', ip='10.0.1.10/24') # Network 10.0.1.0/24
    h2 = net.addHost('h2', ip='10.0.1.11/24')
    h3 = net.addHost('h3', ip='10.0.2.10/24') # Network 10.0.2.0/24
    h4 = net.addHost('h4', ip='10.0.2.11/24')
    h5 = net.addHost('h5', ip='10.0.3.10/24') # Network 10.0.3.0/24
    h6 = net.addHost('h6', ip='10.0.3.11/24')
    
    hosts = [h1, h2, h3, h4, h5, h6]

    info('*** Create links\n')
    # links: host <-> switch
    net.addLink(h1, s1, intfName1='h1-eth0', intfName2='s1-eth1')
    net.addLink(h2, s1, intfName1='h2-eth0', intfName2='s1-eth2')
    net.addLink(h3, s2, intfName1='h3-eth0', intfName2='s2-eth1')
    net.addLink(h4, s2, intfName1='h4-eth0', intfName2='s2-eth2')
    net.addLink(h5, s3, intfName1='h5-eth0', intfName2='s3-eth1')
    net.addLink(h6, s3, intfName1='h6-eth0', intfName2='s3-eth2')
    # links: router <-> switch
    net.addLink(r1, s1, intfName1='r1-eth0', intfName2='s1-eth3') # 10.0.1.1
    net.addLink(r2, s2, intfName1='r2-eth0', intfName2='s2-eth3') # 10.0.2.1
    net.addLink(r3, s3, intfName1='r3-eth0', intfName2='s3-eth3') # 10.0.3.1
    # links: router <-> router
    net.addLink(r1, r2, intfName1='r1-eth1', intfName2='r2-eth1') # 192.168.12.0/24
    net.addLink(r2, r3, intfName1='r2-eth2', intfName2='r3-eth1') # 192.168.23.0/24
    net.addLink(r3, r1, intfName1='r3-eth2', intfName2='r1-eth2') # 192.168.31.0/24

    info('*** Starting network\n')
    net.start()

    info('*** Configure Host IPs and Default Gateway\n')
    h1.cmd('ip addr flush dev h1-eth0; ip addr add 10.0.1.10/24 dev h1-eth0; ip route add default via 10.0.1.1')
    h2.cmd('ip addr flush dev h2-eth0; ip addr add 10.0.1.11/24 dev h2-eth0; ip route add default via 10.0.1.1')
    h3.cmd('ip addr flush dev h3-eth0; ip addr add 10.0.2.10/24 dev h3-eth0; ip route add default via 10.0.2.1')
    h4.cmd('ip addr flush dev h4-eth0; ip addr add 10.0.2.11/24 dev h4-eth0; ip route add default via 10.0.2.1')
    h5.cmd('ip addr flush dev h5-eth0; ip addr add 10.0.3.10/24 dev h5-eth0; ip route add default via 10.0.3.1')
    h6.cmd('ip addr flush dev h6-eth0; ip addr add 10.0.3.11/24 dev h6-eth0; ip route add default via 10.0.3.1')

    info('*** Configure Router Interfaces\n')
    r1.cmd('ifconfig r1-eth0 10.0.1.1/24; ifconfig r1-eth1 192.168.12.1/24; ifconfig r1-eth2 192.168.31.1/24')
    r2.cmd('ifconfig r2-eth0 10.0.2.1/24; ifconfig r2-eth1 192.168.12.2/24; ifconfig r2-eth2 192.168.23.1/24')
    r3.cmd('ifconfig r3-eth0 10.0.3.1/24; ifconfig r3-eth1 192.168.23.2/24; ifconfig r3-eth2 192.168.31.2/24')

    info('*** Add Static Routes on Routers\n')
    r1.cmd('ip route add 10.0.2.0/24 via 192.168.12.2; ip route add 10.0.3.0/24 via 192.168.31.2')
    r2.cmd('ip route add 10.0.1.0/24 via 192.168.12.1; ip route add 10.0.3.0/24 via 192.168.23.2')
    r3.cmd('ip route add 10.0.1.0/24 via 192.168.31.1; ip route add 10.0.2.0/24 via 192.168.23.1')
    
    return net, hosts

def run_ddos_traffic():
    # Start the network
    net, hosts = startNetwork()
    
    # h1 is the first host (10.0.1.10). Assume this is the target server (h1 retained as server based on old 10.0.0.1 role)
    h1 = net.get('h1')

    # Start Webserver on h1 (IP: 10.0.1.10)
    h1.cmd('cd /home/mininet/webserver')
    h1.cmd('python -m SimpleHTTPServer 80 &')
    sleep(2) # Wait for the server to start

    # ------------------ Execute DDOS Traffic ------------------

    # 1. ICMP (Ping) Flood
    src = choice(hosts)
    # Get h1's IP as the DDoS target, since h1 is the server
    dst = h1.IP() # h1's IP is 10.0.1.10
    print("--------------------------------------------------------------------------------")
    print("Performing ICMP (Ping) Flood: {} -> {}".format(src.name, dst))
    print("--------------------------------------------------------------------------------")
    # Change: use hping3 with h1's IP (10.0.1.10) as target
    src.cmd("timeout 20s hping3 -1 -V -d 120 -w 64 -p 80 --rand-source --flood {}".format(dst))
    sleep(100)

    # 2. UDP Flood
    src = choice(hosts)
    dst = h1.IP()
    print("--------------------------------------------------------------------------------")
    print("Performing UDP Flood: {} -> {}".format(src.name, dst))
    print("--------------------------------------------------------------------------------")
    # Change: use hping3 with h1's IP (10.0.1.10) as target
    src.cmd("timeout 20s hping3 -2 -V -d 120 -w 64 --rand-source --flood {}".format(dst))
    sleep(100)

    # 3. TCP-SYN Flood
    src = choice(hosts)
    dst = h1.IP()
    print("--------------------------------------------------------------------------------")
    print("Performing TCP-SYN Flood: {} -> {}".format(src.name, dst))
    print("--------------------------------------------------------------------------------")
    # Change: Target IP is h1 (10.0.1.10)
    src.cmd('timeout 20s hping3 -S -V -d 120 -w 64 -p 80 --rand-source --flood {}'.format(dst))
    sleep(100)

    # 4. LAND Attack
    src = choice(hosts)
    dst = h1.IP()
    print("--------------------------------------------------------------------------------")
    print("Performing LAND Attack: {} -> {}".format(src.name, dst))
    print("--------------------------------------------------------------------------------")
    # Change: Target IP is h1 (10.0.1.10). LAND Attack: source IP = destination IP
    src.cmd("timeout 20s hping3 -1 -V -d 120 -w 64 --flood -a {} {}".format(dst, dst))
    sleep(100)
    print("--------------------------------------------------------------------------------")

    net.stop()

if __name__ == '__main__':
    start = datetime.now()
    setLogLevel( 'info' )
    run_ddos_traffic()
    end = datetime.now()
    print(end-start)