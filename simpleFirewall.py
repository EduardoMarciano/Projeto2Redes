from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch, Host
from mininet.link import TCLink

def create_firewall(net, host1, host2):
    # Adding firewall rule to block communication between host1 and host2
    host1.cmd('iptables -A OUTPUT -d {} -j DROP'.format(host2.IP()))
    host2.cmd('iptables -A OUTPUT -d {} -j DROP'.format(host1.IP()))

def clear_firewall_rules(net):
    # Clearing all firewall rules on each host
    for host in net.hosts:
        host.cmd('iptables -F')

def create_topology():
    net = Mininet(controller=Controller, switch=OVSSwitch, link=TCLink)

    # Adding the controller and connecting it to all switches
    controller = net.addController('c0')

    # Adding switches
    switches = [net.addSwitch('s{}'.format(i), controller=controller) for i in range(1, 6)]

    # Adding hosts
    hosts = [net.addHost('h{}'.format(i)) for i in range(1, 11)]

    # Linking switches to hosts
    for i in range(0, 10, 2):
        net.addLink(switches[i // 2], hosts[i])
        net.addLink(switches[i // 2], hosts[i + 1])

    # Linking switches together
    for i in range(4):
        net.addLink(switches[i], switches[i + 1])

    # Starting the network
    net.start()

    # Adding the firewall rule to block communication between host1 and host2
    create_firewall(net, hosts[0], hosts[1])

    # Adding a rule to avoid dropping packets due to the firewall
    for host in net.hosts:
        host.cmd('ip route add 0.0.0.0/0 via 10.0.0.254')  # Assuming 10.0.0.254 is the IP of the gateway

    # Running CLI
    net.interact()

    # Stopping the network and cleaning up
    net.stop()
    clear_firewall_rules(net)

if __name__ == '__main__':
    create_topology()
