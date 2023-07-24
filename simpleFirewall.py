from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch, Host
from mininet.link import TCLink

# Firewall blocking communication between 2 Hosts
def create_firewall(net, host1, host2):
    host1.cmd('iptables -A OUTPUT -d {} -j DROP'.format(host2.IP()))
    host2.cmd('iptables -A OUTPUT -d {} -j DROP'.format(host1.IP()))

def clear_firewall_rules(net):
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
    
    print("Todos os Hosts possuem conectividade entre si.")
    net.pingAll()

    # Instantiate the Firewall    
    create_firewall(net, hosts[0], hosts[1])

    # Adding a rule to avoid dropping packets due to the firewall
    for host in net.hosts:
        host.cmd('ip route add 0.0.0.0/0 via 10.0.0.254')

    print("Host 1 e Host 2 pararam de se comunicar após inserção do firewall")
    net.pingAll()

    # Running CLI
    net.interact()

    net.stop()
    clear_firewall_rules(net)