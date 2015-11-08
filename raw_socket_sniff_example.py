#!/usr/bin/env python
# -*- coding: utf-8 -*-

################################################################################
## raw_socket_sniff_example.py Software Developer SACKUFPI                    ##
##                                                                            ##
## Yoandrys Peña Meriño                                                       ##
## MsC. Computer SCience                                                      ##
## Eng. Telecommunications and Electronic                                     ##                           
## Buenos Aires, Argentina                                                    ##
## Copyright (C) 2015 <yoandrisp2007@gmail.com>                               ##                                                             
##                                                                            ##
################################################################################

import socket
import struct
import binascii
import time
import uuid

ETHER_BROADCAST="\xff"*6
ETH_P_ETHER=0x0001
ETH_P_IP= '\x08\x00' #0x0800
ETH_P_ARP = '\x08\x06' #0x0806
ETH_P_EVERYTHING = 0x0003

class SniffServer(object):

    def __init__(self):
        self.sniff_sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_EVERYTHING))   #socket.htons(0x806)) only arp packet

    def run(self):
        self.capture()

    def capture(self):
        print 'PROTO    SOURCE_MAC    SOURCE_IPADDRESS:PORT  ---------------->  DEST_MAC    DEST_IPADDRESS:PORT    TTL'
        while True:
            try:
                pkt = self.sniff_sock.recvfrom(2048)
                ethhead = pkt[0][:14]
                eth = struct.unpack('!6s6s2s', ethhead)
                dest_mac = binascii.hexlify(eth[0])
                source_mac = binascii.hexlify(eth[1])
                frame_type = eth[2]#binascii.hexlify(eth[2])
                
                if frame_type == ETH_P_ARP:
                    arpheader = pkt[0][14:42]
                    arp_hdr = struct.unpack("!2s2s1s1s2s6s4s6s4s", arpheader)

                    print "$$$$$$$$$$$$$$$ ARP HEADER $$$$$$$$$$$$$$$$$$$$"
                    print "Hardware type:   ", binascii.hexlify(arp_hdr[0])
                    print "Protocol type:   ", binascii.hexlify(arp_hdr[1])
                    print "Hardware size:   ", binascii.hexlify(arp_hdr[2])
                    print "Protocol size:   ", binascii.hexlify(arp_hdr[3])
                    print "Opcode:          ", binascii.hexlify(arp_hdr[4])
                    print "Source MAC:      ", binascii.hexlify(arp_hdr[5])
                    print "Source IP:       ", socket.inet_ntoa(arp_hdr[6])
                    print "Dest MAC:        ", binascii.hexlify(arp_hdr[7])
                    print "Dest IP:         ", socket.inet_ntoa(arp_hdr[8])
                    print "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n"
                elif frame_type == ETH_P_IP:
                    ipheader = pkt[0][14:34] #20 bytes 
                    ip_hdr = struct.unpack('!BBHHHBBH4s4s', ipheader)
                    ip_version = ip_hdr[0] >> 4  # IPv4 = 100 or IPv6 = 110                  
                    # for normal header size minimum ip_ihl is 5 word (20 bytes) and maximun 15 word (60 bytes) (word=32bits)                   
                    ip_ihl = ip_hdr[0] & 0xF # word number of 32 bits current in datagram
                    ip_hdr_length = ip_ihl*4 # length in bytes
                    ip_tos = ip_hdr[1]
                    ip_total_length = ip_hdr[2]
                    ip_identifier = ip_hdr[3]
                    ip_flags = ip_hdr[4] >> 13 #only 3 bits most significant
                    ip_fragment_position = ip_hdr[4] & 0x1FFF #only 13 bits least significant                        
                    ip_ttl = ip_hdr[5]
                    ip_proto_id = ip_hdr[6]
                    protocols = self.get_constants('IPPROTO_')
                    protocol = protocols[ip_proto_id]
                    ip_sum_header_control = ip_hdr[7]
                    ip_source_ipaddress = socket.inet_ntoa(ip_hdr[8])
                    ip_dest_ipaddress = socket.inet_ntoa(ip_hdr[9])
                    slice_init = 14 + ip_hdr_length
                    if ip_proto_id == socket.IPPROTO_TCP:
                        tcpheader = pkt[0][slice_init: slice_init + 20]
                        tcp_hdr = struct.unpack('!HHLLHHHH', tcpheader)
                        tcp_source_port = tcp_hdr[0]
                        tcp_dest_port = tcp_hdr[1]
                        tcp_sequence_number = tcp_hdr[2]
                        tcp_acknowledge_number = tcp_hdr[3]
                        tcp_header_length = tcp_hdr[4] >> 12 # number of 32 bits words in tcp 
                        tcp_total_header_length = tcp_header_length*4 #total header length in bytes 
#                        tcp_reserved = 000 #for future use
                        tcp_flags = tcp_hdr[4] & 0x1FF
                        tcp_window_length = tcp_hdr[5]
                        tcp_verification_sum = tcp_hdr[6]
                        tcp_urgent_pointer = tcp_hdr[7]
                        sum_eth_ip_tcp_headers = 14 + ip_hdr_length + tcp_total_header_length
                        size_payload_in_tcp_package = len(pkt[0]) - sum_eth_ip_tcp_headers # size all data in tcp package
                        raw_payload = pkt[0][sum_eth_ip_tcp_headers:] # read all data in tcp package
#                        print "size_data=%s ANDDDDDDDDDDDDDD  = %s" % (size_payload_in_tcp_package, raw_payload)
                        print '%s     %s    %s:%s  ---------------->  %s    %s:%s    %s' % \
                        (protocol[8:], source_mac, ip_source_ipaddress, tcp_source_port, dest_mac, ip_dest_ipaddress, tcp_dest_port, ip_ttl)
#                        print raw_payload
                    elif ip_proto_id == socket.IPPROTO_UDP:
                        udpheader = pkt[0][slice_init: slice_init + 8]#20]
                        udp_hdr = struct.unpack('!HHHH', udpheader)
                        udp_source_port = udp_hdr[0]            
                        udp_dest_port = udp_hdr[1]
                        udp_header_payload_length = udp_hdr[2]
                        udp_verification_sum = udp_hdr[3]
                        sum_eth_ip_udp_headers = 14 + ip_hdr_length + 8   
                        size_payload_in_udp_package = len(pkt[0]) - sum_eth_ip_udp_headers # size all data in tcp package
                        raw_payload = pkt[0][sum_eth_ip_udp_headers:] # read all data in udp package
#                        print "TOATL=%s HR=%s PAYLOAD=%s" % (udp_header_payload_length, 8, size_payload_in_udp_package)
#                        print "size_data=%s ANDDDDDDDDDDDDDD  = %s" % (size_payload_in_udp_package, raw_payload)
                        print '%s     %s    %s:%s  ---------------->  %s    %s:%s    %s' % \
                        (protocol[8:], source_mac, ip_source_ipaddress, udp_source_port, dest_mac, ip_dest_ipaddress, udp_dest_port, ip_ttl)
                    elif ip_proto_id == socket.IPPROTO_ICMP:
                        icmpheader = pkt[0][34:42] # icmp package is 8 bytes of icmp header + IP header + first 64 bist of the datagram
                        icmp_hdr = struct.unpack('!B7s', icmpheader)
                        icmp_type = icmp_hdr[0]
                        icmp_description = ''
                        if icmp_type == 0:
                            icmp_description = 'ECHO REPLY'
                        print '%s     %s    %s  ---------------->  %s    %s    %s    TYPE=%s (%s)' % \
                        (protocol[8:], source_mac, ip_source_ipaddress, dest_mac, ip_dest_ipaddress, ip_ttl, icmp_type, icmp_description)
                    else:
                        print '---------- Receiving Other packet from protocol %s ---------' % protocol[8:]
            except struct.error:
                print 'Invalid Header'            

    def get_constants(self, prefix):
        """Create a dictionary mapping socket module constants to their names."""
        return dict( (getattr(socket, n), n)
                     for n in dir(socket)
                     if n.startswith(prefix)
                     )

    def change_mac_address(self, new_mac_address):
#        ifconfig eth0 down
#        ifconfig eth0 hw ether 00:80:48:BA:d1:30
#        ifconfig eth0 up
        pass
    
    def get_local_mac_address(self, interface=None):
    #       ifconfig eth0 | grep HWaddr |cut -dH -f2|cut -d\  -f2
    #       00:26:6c:df:c3:95
        local_mac = ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0,8*6,8)][::-1])
        return local_mac

    def get_mac_address(self, ip_victims):
        mac_victims = dict.fromkeys(ip_victims)
        #return dict mac_victims = {'ip_a': 00:ab:fa:aa:01:20, 'ip_b':......}    
        pass

    def arp_spoof(self, ip_poison, ip_victims=[], local_mac=None, interface="wlan0"):
        if ip_poison:
            sock_arp_spoof = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0806))
            sock_arp_spoof.bind((interface, socket.htons(0x0806)))
            if local_mac:
                mac_source = local_mac
            else: mac_source = self.get_local_mac_address()
            
            code ='\x08\x06'
            htype = '\x00\x01'
            protype = '\x08\x00'
            hsize = '\x06'
            psize = '\x04'
            opcode = '\x00\x02'
            ip_poison_formated = socket.inet_aton(ip_poison)
            if ip_victims:
                mac_victims = self.get_mac_address(ip_victims)
                arp_victims = {}
                for ip_address in mac_victims:
                    ip_address_formated = socket.inet_aton(ip_address)
                    eth = mac_victims[ip_address] + mac_source + code
                    arp_victim = eth + htype + protype + hsize + psize + opcode + mac_source + ip_poison_formated + mac_victims[ip_address] + ip_address_formated
                    arp_victims[ip_address] = arp_victim                 
            else:
                pass #send all ip network Ex:192.168.1.0  mac_dest = '\xFF\xFF\xFF\xFF\xFF\xFF'          
        
            while True:
                for arp_victim in arp_victims: 
                    sock_arp_spoof.send(arp_victim)  
            

if __name__ == '__main__':
    sniff_server = SniffServer()  
    sniff_server.run()  
