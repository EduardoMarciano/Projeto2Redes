import select
import errno
import time
from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch, Host
from mininet.link import TCLink

def prompt_firewall():
    while True:
        response = input("Do you want to disable the firewall or exit the loop? (yes/no/exit): ").strip().lower()

        if response in {'yes', 'y'}:
            disable_firewall(net)
        elif response in {'no', 'n'}:
            print("Firewall activated.")
            activate_firewall(net)
        elif response in {'exit'}:
            break
        else:
            print("Invalid input. Please enter 'yes', 'no', or 'exit'.")

def disable_firewall(net):
    clear_firewall_rules(net)
    
    print("Firewall rules have been cleared.")
    net.pingAll()

def activate_firewall(net):
    print("Blocking communication between H1 and H2.")
    print("Blocking UDP communication between H3 and H4.")
    print("Blocking TCP communication between H5 and H6.")
    block_communication(hosts[0], hosts[1])
    block_protocol(hosts[2], hosts[3], 'udp')
    block_protocol(hosts[4], hosts[5], 'tcp')
    
    print("Firewall rules have been activated.")
    net.pingAll()

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


def block_protocol(host1, host2, protocol):
    # Adding firewall rule to block communication between host1 and host2
    if protocol == 'tcp':
        host1.cmd('iptables -A OUTPUT -p tcp -d {} -j DROP'.format(host2.IP()))
        host2.cmd('iptables -A OUTPUT -p tcp -d {} -j DROP'.format(host1.IP()))
    elif protocol == 'udp':
        host1.cmd('iptables -A OUTPUT -p udp -d {} -j DROP'.format(host2.IP()))
        host2.cmd('iptables -A OUTPUT -p udp -d {} -j DROP'.format(host1.IP()))

def allow_protocol(host1, host2, protocol):
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

    # Start of experiments and simulations in the network
    print()
    print("All Hosts have connectivity with each other.\n")
    net.pingAll()
    
    block_communication(hosts[0], hosts[1])
    
    print()
    print("Host 1 and Host 2 stopped communicating after the firewall block.\n")
    net.pingAll()
    
    allow_communication(hosts[0], hosts[1])
    
    print()
    print("Host 1 and Host 2 resume communication after removing the firewall block.\n")
    net.pingAll()
    
    print()
    print("Blocking communication between H1 and H2.\n")
    # Blocking communication (h1 and h2)
    block_communication(hosts[0], hosts[1])
    print("Blocking UDP communication between H3 and H4.\n")
    # Blocking udp (h3 and h4)
    block_protocol(hosts[2], hosts[3], 'udp')
    print("Blocking TCP communication between H5 and H6.\n")
    # Blocking tcp (h5 and h6)
    block_protocol(hosts[4], hosts[5], 'tcp')
    
    # Enter a loop that asks to disable or activate the firewall
    prompt_firewall()
    
    # Running CLI
    net.interact()

    clear_firewall_rules(net)
    net.stop()
