#!/usr/bin/env python3

"""

scans clients of network

TODO fix bug with range

"""


import scapy.all as scapy

import argparse


def get_args():
    parser = argparse.ArgumentParser()

    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP range")

    options = parser.parse_args()

    if not options.target:
        parser.error("[-] Please specify an target, use --help for more info")

    return options



def scan(ip):
    # create arp packet
    arp_request = scapy.ARP(pdst=ip)
    #
    # create broadcast frame
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff') # ff:ff:ff:ff:ff:ff - broadcast address
    arp_request_broadcast = broadcast/arp_request # combine packets
    #
    # send arp packet
    answered_list = scapy.srp(arp_request_broadcast, timeout = 0.5, verbose=False)[0]
    #
    # create clients list
    clients_list = []
    for answer in answered_list:
        client_dict = {"ip": answer[1].psrc, "mac": answer[1].hwsrc}
        clients_list.append(client_dict)
    #
    return clients_list


def print_result(result_list: object):
    """
    receives result of scan function (clients list) and prints it
    """

    # horizontal line
    hr = ("-" * 50)

    print("\n")
    if len(result_list) > 0:
        print("IP\t\t\tMAC Address\n" + hr)
        for client in result_list:
            print(client["ip"] + '\t\t' + client["mac"])
    else:
        print("Nothing")
    print("\n")




if __name__ == "__main__":
    options = get_args()

    target = options.target

    print_result(
        result_list = scan(target)
    )

    # for i in range(0, 255):
    #     a = scan('192.168.0.'+str(i))
    #     if a:
    #         print(a)