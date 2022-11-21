# prerequisites
```
sudo apt-get install python3-scapy
```




____
## create and activate virtual evironment
```
virtualenv myvenv

activate virtualenv
```


## install requirements
```
pip3 install reqs.txt
```

____
# Using

## arp spoofing ->
```
sudo python3.8 arp_spoof.py -t=192.168.0.100 -g=192.168.0.1
```

  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Target IP. Victim.
  -g GATEWAY, --gateway GATEWAY
                        Gateway IP. Wifi router, for example



### if this blocks client internet, run this
```
sudo iptables -P FORWARD ACCEPT
```

____

## packet sniffer
python3 packet_sniffer.py

### this will show insecure http packets

