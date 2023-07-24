import select
import errno
import time
from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch, Host
from mininet.link import TCLink

def drop_udp_connection(net):
    for host1 in net.hosts:
        for host2 in net.hosts:
            if host1 != host2:
                host1.cmd('iptables -A OUTPUT -p udp -d {} -j DROP'.format(host2.IP()))


def block_communication(host1, host2):
    # Adding firewall rule to block communication between host1 and host2
    host1.cmd('iptables -A OUTPUT -d {} -j DROP'.format(host2.IP()))
    host2.cmd('iptables -A OUTPUT -d {} -j DROP'.format(host1.IP()))

def allow_communication(host1, host2):
    # Removing firewall rule to allow communication between host1 and host2
    host1.cmd('iptables -D OUTPUT -d {} -j DROP'.format(host2.IP()))
    host2.cmd('iptables -D OUTPUT -d {} -j DROP'.format(host1.IP()))


def blockProtocolo(host1, host2, protocol):
    # Adding firewall rule to block communication between host1 and host2
    if protocol == 'tcp':
        host1.cmd('iptables -A OUTPUT -p tcp -d {} -j DROP'.format(host2.IP()))
        host2.cmd('iptables -A OUTPUT -p tcp -d {} -j DROP'.format(host1.IP()))
    elif protocol == 'udp':
        host1.cmd('iptables -A OUTPUT -p udp -d {} -j DROP'.format(host2.IP()))
        host2.cmd('iptables -A OUTPUT -p udp -d {} -j DROP'.format(host1.IP()))

def allowProtocolo(host1, host2, protocol):
    # Removing firewall rule to allow communication between host1 and host2
    if protocol == 'tcp':
        host1.cmd('iptables -D OUTPUT -p tcp -d {} -j DROP'.format(host2.IP()))
        host2.cmd('iptables -D OUTPUT -p tcp -d {} -j DROP'.format(host1.IP()))
    elif protocol == 'udp':
        host1.cmd('iptables -D OUTPUT -p udp -d {} -j DROP'.format(host2.IP()))
        host2.cmd('iptables -D OUTPUT -p udp -d {} -j DROP'.format(host1.IP()))

def clear_firewall_rules(net):
    # Clearing all firewall rules on each host
    for host in net.hosts:
        host.cmd('iptables -F')

def create_topology(net, controller, switches, hosts):
    # Linking switches to hosts
    for i in range(0, 10, 2):
        net.addLink(switches[i // 2], hosts[i])
        net.addLink(switches[i // 2], hosts[i + 1])

    # Linking switches together
    for i in range(4):
        net.addLink(switches[i], switches[i + 1])

if __name__ == '__main__':
    net = Mininet(controller=Controller, switch=OVSSwitch, link=TCLink)
    
    controller = net.addController('c0')
    switches = [net.addSwitch('s{}'.format(i), controller=controller) for i in range(1, 6)]
    hosts = [net.addHost('h{}'.format(i)) for i in range(1, 11)]
    
    create_topology(net, controller, switches, hosts)

    # Starting the network
    net.start()
    
    # Adding a rule to avoid dropping packets due to the firewall
    for host in net.hosts:
        host.cmd('ip route add 0.0.0.0/0 via 10.0.0.254')

    # Inicio de experimentos e simulacoes na rede
    print()
    print("Todos os Hosts possuem conectividade entre si. \n")
    net.pingAll()
    
    block_communication(hosts[0], hosts[1])
    
    print()
    print("Host 1 e Host 2 pararam de se comunicar após inserção do bloqueio do firewall \n")
    net.pingAll()
    
    allow_communication(hosts[0], hosts[1])
    
    print()
    print("Host 1 e Host 2 voltam a se comunicar ao se retirar o bloqueio. \n")
    net.pingAll()
    
    print()
    print("Bloqueio algumas conecções. \n")
    
    # Blocking communication (h1 and h2)
    block_communication(hosts[0], hosts[1])

    # Blocking udp (h3 and h4)
    blockProtocolo(hosts[2], hosts[3], 'udp')

    # Blocking tcp (h5 and h6)
    blockProtocolo(hosts[4], hosts[5], 'tcp')

    # Running CLI
    net.interact()

    clear_firewall_rules(net)
    net.stop()
