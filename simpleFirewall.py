import time
from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch, Host
from mininet.link import TCLink

def prompt_firewall():
    while True:
        print("Options:")
        print("1. Enable Firewall")
        print("2. Disable Firewall")
        print("3. Send Message")
        print("4. Block Connection between two hosts")
        print("5. Unblock Connection between two hosts")
        print("6. Exit Loop")

        response = input("Enter the option number: ").strip().lower()

        if response == '1':
            activate_firewall(net)

        elif response == '2':
            disable_firewall(net)

        elif response == '3':
            send_message()

        elif response == '4':
            block_connection()

        elif response == '5':
            allow_connection()

        elif response == '6':
            print("Exiting the loop.")
            break
        else:
            print("Invalid input. Please enter a valid option number (1, 2, 3, 4, 5, or 6).")

def block_connection():
    while True:
        host1_name = input("Enter the name of the first host: ").strip().lower()
        host2_name = input("Enter the name of the second host: ").strip().lower()

        if host1_name not in [host.name for host in net.hosts] or host2_name not in [host.name for host in net.hosts]:
            print("Invalid host names. Please enter valid host names.")
            continue

        elif host1_name == host2_name:
            print("The two hosts cannot be the same.")
            continue

        host1 = [host for host in net.hosts if host.name == host1_name][0]
        host2 = [host for host in net.hosts if host.name == host2_name][0]

        block_protocol_option = input("Enter the protocol to block (TCP, UDP, or both): ").strip().lower()

        if block_protocol_option == 'tcp':
            block_protocol(host1, host2, 'tcp')
            print(f"Blocked TCP communication between {host1_name} and {host2_name}.")
            break
        elif block_protocol_option == 'udp':
            block_protocol(host1, host2, 'udp')
            print(f"Blocked UDP communication between {host1_name} and {host2_name}.")
            break
        elif block_protocol_option == 'both':
            block_communication(host1, host2)
            print(f"Blocked both TCP and UDP communication between {host1_name} and {host2_name}.")
            break
        else:
            print("Invalid protocol option. Please enter 'TCP', 'UDP', or 'both'.")

def allow_connection():
    while True:
        host1 = input("Enter the name of the first host: ").strip().lower()
        host2 = input("Enter the name of the second host: ").strip().lower()

        if host1 not in [host.name for host in net.hosts] or host2 not in [host.name for host in net.hosts]:
            print("Invalid host names. Please enter valid host names.")
            continue

        elif host1 == host2:
            print("The two hosts cannot be the same.")
            continue
        
        host1 = [host for host in net.hosts if host.name == host1][0]
        host2 = [host for host in net.hosts if host.name == host2][0]
        
        protocol = input("Enter the protocol to unblock (TCP, UDP, or both): ").strip().lower()

        if protocol == 'tcp':

            allow_protocol(host1, host2, protocol)
            print(f"Unblocked TCP communication between {host1} and {host2}.")

            break

        elif protocol == 'udp':

            allow_protocol(host1, host2, protocol)
            print(f"Unblocked UDP communication between {host1} and {host2}.")

            break

        elif protocol == 'both':

            allow_communication(host1, host2)
            print(f"Unblocked both TCP and UDP communication between {host1} and {host2}.")

            break
        else:
            print("Invalid protocol option. Please enter 'TCP', 'UDP', or 'both'.")

def send_message():
    while True:
        protocol = input("Enter the protocol (TCP or UDP): ").strip().lower()
        host_origin = input("Enter the source host: ").strip().lower()
        host_destiny = input("Enter the destination host: ").strip().lower()

        if protocol not in {'tcp', 'udp'}:
            print("Invalid protocol. Please enter either 'tcp' or 'udp'.")
            continue

        elif host_origin not in [host.name for host in net.hosts]:
            print("Invalid source host. Please enter a valid host name.")
            continue

        elif host_destiny not in [host.name for host in net.hosts]:
            print("Invalid destination host. Please enter a valid host name.")
            continue

        elif host_origin == host_destiny:
            print("Source host cannot be the same as the destination host.")
            continue

        host_origin = [host for host in net.hosts if host.name == host_origin][0]
        host_destiny = [host for host in net.hosts if host.name == host_destiny][0]

        if protocol == 'tcp':
            host_origin.cmd('xterm -hold -e "iperf -s -i 1" &')
            time.sleep(1)
            host_destiny.cmd('xterm -hold -e "iperf -c {} -t 10 -i 1" &'.format(host_origin.IP()))
            print("TCP message was sent")
            break

        elif protocol == 'udp':
            host_destiny.cmd('xterm -hold -e "iperf -s -u -i 1" &')
            time.sleep(1)
            host_origin.cmd('xterm -hold -e "iperf -c {} -u -b 1m -n 1000" &'.format(host_destiny.IP()))
            print("UDP message was sent")
            break

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
    #net.pingAll()
    
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