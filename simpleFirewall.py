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

def clear_firewall_rules(net):
    # Clearing all firewall rules on each host
    for host in net.hosts:
        host.cmd('iptables -F')

def send_tcp_message(sender, receiver, message):
    receiver.cmd('nc -l -p 12345 > /tmp/message &')
    sender.cmd('echo "{}" | nc {} 12345'.format(message, receiver.IP()))

def receive_tcp_message(receiver):
    return receiver.cmd('cat /tmp/message')

def send_udp_message(sender, receiver, message):
    receiver.cmd('nc -u -l -p 12345 > /tmp/message &')
    sender.cmd('echo "{}" | nc -u {} 12345'.format(message, receiver.IP()))

def receive_udp_message(receiver):
    return receiver.cmd('cat /tmp/message')

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

    #Inicio de experimentos e simulações na rede
    print("Todos os Hosts possuem conectividade entre si.\n")
    net.pingAll()

    block_communication(hosts[0], hosts[1])
    print("Host 1 e Host 2 pararam de se comunicar após inserção do bloqueio do firewall.\n")
    net.pingAll()

    allow_communication(hosts[0], hosts[1])
    print("Host 1 e Host 2 voltam a se comunicar ao se retirar o bloqueio.\n")
    net.pingAll()

    print("Bloqueio das conecções UDP em toda a rede.\n")
    drop_udp_connection(net)
    
    
    for i in range(1, 10, 2):
        next_host = (i + 2) if i < 9 else 1  # Próximo host (o último host envia para o primeiro)
        send_udp_message(net.get('h{}'.format(i)), net.get('h{}'.format(next_host)), "Mensagem UDP de {} para {}".format(i, next_host))
        received_message = receive_udp_message(net.get('h{}'.format(next_host)))
        print("Mensagem UDP recebida no host {}: {}".format(next_host, received_message.strip()))

    # Enviar mensagens TCP entre hosts pares
    for i in range(2, 10, 2):
        next_host = (i + 2) if i < 8 else 1  # Próximo host (o penúltimo host envia para o primeiro)
        send_tcp_message(net.get('h{}'.format(i)), net.get('h{}'.format(next_host)), "Mensagem TCP de {} para {}".format(i, next_host))
        received_message = receive_tcp_message(net.get('h{}'.format(next_host)))
        print("Mensagem TCP recebida no host {}: {}".format(next_host, received_message.strip()))

    # Running CLI
    net.interact()

    net.stop()
    clear_firewall_rules(net)
