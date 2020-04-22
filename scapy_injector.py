#!/usr/bin/env python3

import scapy.all as scapy
from scapy.layers import http
from config import PORT, DEFAULT_CONTENT
import sys



def make_response(src_ip, dst_ip, sport, dport, ack, seq, tcp_seg_len, tcp_flags='PFA', content=DEFAULT_CONTENT):
    ip = scapy.IP(src = dst_ip, dst = src_ip) 
    tcp = scapy.TCP(sport = dport, dport = sport, seq = ack, ack = seq + tcp_seg_len, flags=tcp_flags) 
    tcp.window = 512

    http_resp = http.HTTPResponse()
    
    response = ip / tcp / http_resp / content
    
    return response

def send_multi_resp(src_ip, dst_ip, sport, dport, ack, seq, tcp_seg_len):
    num_packets = 5

    add_to_seq = 0

    for packet in range(num_packets-1):
        content = 'packet number = {}\r\n'.format(packet)

        resp = make_response(src_ip, dst_ip, sport, dport, ack, seq, tcp_seg_len, tcp_flags='PA', content=content)
        resp[scapy.TCP].seq += add_to_seq

        print(resp[scapy.TCP].seq)

        add_to_seq += len(content)

        scapy.send(resp)
        print(resp.summary())


    resp = make_response(src_ip, dst_ip, sport, dport, ack, seq, tcp_seg_len, tcp_flags='PFA', content='end\r\n\r\n')
    resp[scapy.TCP].seq += add_to_seq
    scapy.send(resp)
    print(resp.summary())


def handle_packet(packet):
    print (packet.show())

    src_ip = packet[scapy.IP].src
    dst_ip = packet[scapy.IP].dst
    sport = packet[scapy.TCP].sport
    dport = packet[scapy.TCP].dport
    ack = packet[scapy.TCP].ack
    seq = packet[scapy.TCP].seq

    tcp_seg_len = len(packet[scapy.Raw].load)

    resp = send_multi_resp(src_ip, dst_ip, sport, dport, ack, seq, tcp_seg_len)


def filter_packet_m (packet):
    if (not scapy.TCP in packet):
        return False

    if (packet[scapy.TCP].dport == PORT and packet[scapy.TCP].flags == 'PA'):
        return True
    else:
        return False
   
def main():
    # filter_str = "tcp and port " + str(PORT) + " and (tcp[tcpflags] & tcp-ack !=0) and (tcp[tcpflags] & tcp-push !=0)"
    # filter_str = "tcp and port " + str(port) + " port 80 and tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420"
    # print("Filter: {}".format(filter_str))

    scapy.conf.L3socket = scapy.L3RawSocket

    if len(sys.argv) != 2:
    	print("Usage: {} <interface>".format(sys.argv[0]))
    	return

    iface = sys.argv[1]

    print("Port: {}\nInterface: {}".format(PORT, iface))

    scapy.sniff(prn=handle_packet, lfilter=filter_packet_m, iface=iface)
    return


if __name__ == "__main__":
    main()

    