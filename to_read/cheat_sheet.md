# change mac. But first save your current mac-address somewhere
```
python3 mac_changer.py --interface=wlo1  --mac=18:47:3d:d7:07:45
```

pwd

man ls



#change max address
ifconfig eth0 down
ifconfig eth0 hw ether 00:11:22:33:44:55
ifconfig eth0 up


arp_request.show()

print(arp_request.show())

# get all fields
scapy.ls(scapy.ARP())


send arp packet -> scapy.arping("192.168.0.100")




# sudo netdiscover -r 192.168.0.1/24
# sudo netdiscover -r 192.168.0.1/24
# sudo sudo netdiscover -r 192.168.0.1/16


# 18:47:3d:d7:07:45


alias python3='/usr/bin/python3.6'