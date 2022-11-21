

"""

dependencies -> 

<!-- sudo apt install python3-pip git libnfnetlink-dev libnetfilter-queue-dev
pip3 install -U git+https://github.com/kti/python-netfilterqueue -->
<!-- apt-get install build-essential python-dev libnetfilter-queue-dev -->
<!-- sudo pip3 install NetfilterQueue -->




в scapy нельзя реализовать отброс оригинального запроса.
Точке доступа нужно отправить и оригинальный, и смодифицированный.
Точка доступа сама выберет, какой запрос выполнить, обычно это запрос, который пришёл раньше.
На модификацию запроса уходит какое-то время, поэтому оригинальный будет быстрее.
А так как нельзя просто остановить оригинальный пакет, нужно помещать пакеты в очередь.


нам нужно создать очередь, а затем с питоном получить доступ к этой очереди

sudo iptables -I FORWARD -j NFQUEUE --queue-num 0

sudo iptables -L

sudo iptables --flush


['__class__', '__delattr__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__le__', '__lt__', '__ne__', '__new__', '__pyx_vtable__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__setstate__', '__sizeof__', '__str__', '__subclasshook__', 'accept', 'drop', 'get_hw', 'get_mark', 'get_payload', 'get_payload_len', 'get_timestamp', 'hook', 'hw_protocol', 'id', 'mark', 'repeat', 'retain', 'set_mark', 'set_payload']


"""



from netfilterqueue import NetfilterQueue


def process_packet(packet):
    print( packet )

    # accept packet
    packet.accept()
    #packet.drop()


print("q")
queue = NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
