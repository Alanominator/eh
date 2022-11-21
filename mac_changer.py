#!/usr/bin/env python3

import subprocess
import argparse
import re



def get_args():
    parser = argparse.ArgumentParser()

    # add our options
    parser.add_argument("-i", "--interface", dest="interface", help="Interface to change its MAC address")
    parser.add_argument("-m", "--mac", dest="new_mac", help="New MAC address")

    options = parser.parse_args()

    # check if the options are specified
    if not options.interface:
        parser.error("[-] Please specify an interface, use --help for more info")
    elif not options.new_mac:
        parser.error("[-] Please specify an mac_address, use --help for more info")

    return options



def change_mac(interface: str, new_mac: str) -> None:
    print(f"[+] Changing MAC address for {interface} to {new_mac}")

    subprocess.call(['sudo', 'ifconfig', interface, 'down'])
    subprocess.call(['sudo' ,'ifconfig', interface, 'hw', 'ether', new_mac])
    subprocess.call(['sudo','ifconfig', interface, 'up'])


def get_current_mac_address(interface):
    # run command
    ifconfig_result = str(subprocess.check_output(['ifconfig', interface]))

    # search mac address in result
    mac_address_search_result = re.search(r'\w\w:\w\w:\w\w:\w\w:\w\w:\w\w', ifconfig_result)


    if mac_address_search_result:
        return mac_address_search_result.group(0)
    else:
        print('[-] Could not read MAC address')









if __name__ == '__main__':
    
    # get terminal options
    options = get_args()

    # try to change mac address 
    change_mac(interface=options.interface, new_mac=options.new_mac)

    # check if mac address was changed
    current_mac = get_current_mac_address(options.interface)

    if current_mac == options.new_mac:
        print(f"[+] MAC address was successfully changed to {current_mac}")
    else:
        print('[-] MAC address did not get changed')

