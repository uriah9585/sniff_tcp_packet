#! /usr/bin/env python

import socket, sys
from struct import *
 

#create an INET, STREAMing socket
class Socket_listing(socket.socket):
    '''
    Socket Server handle messages
    '''

    def __init__(self):
        # create socket
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            self.__RECV_BUFFER = 65565

        except socket.error , msg:
            print 'Socket could not be created. Error Code : {0} Message {1}'.format(msg[0],msg[1])
            sys.exit()
    
    def recv_msg(self):
        # receive a packet
        self.data_recv = self.server.recvfrom( self.__RECV_BUFFER )
        return self.data_recv     



class Ip_header():

    def __init__(self,data):
        self.packet = data[0]
        #take first 20 characters for the ip header unpacked.
        self.ip_header = unpack('!BBHHHBBH4s4s',self.packet[0:20])
        self.version = self.ip_header[0] >> 4
        self.ihl = self.ip_header[0] & 0xF
        #give us the location of data starting
        self.iph_length = self.ihl * 4
        self.ttl = self.ip_header[5]
        self.protocol = self.ip_header[6]
        self.src_addr = socket.inet_ntoa(self.ip_header[8])
        self.dst_addr = socket.inet_ntoa(self.ip_header[9])

    def print_ip_header(self):
        # Print the header in return it 
        print '############ IP #############'
        print 'Version              : {0}'.format(self.version)
        print 'IP Header Length     : {0}'.format(self.ihl)
        print 'TTL                  : {0}'.format(self.ttl)
        print 'protocol             : {0}'.format(self.protocol)
        print 'Source Address       : {0}'.format(self.src_addr)
        print 'Destination Address  : {0}'.format(self.dst_addr)
        print '############ IP #############'
        
        return 

class Tcp_header():

    def __init__(self,data):
        self.tcp_header = unpack('!HHLLBBHHH',data)
        self.source_port = self.tcp_header[0]
        self.dest_port = self.tcp_header[1]
        self.sequence = self.tcp_header[2]
        self.acknowledgement = self.tcp_header[3]
        self.doff_reserved = self.tcp_header[4]
        self.tcph_length = self.doff_reserved >> 4

    def print_tcp_header(self):
        # Print the header in return it 
        print '############ TCP ###########'
        print 'Source Port          : {0}'.format(self.source_port)
        print 'Dest Port            : {0}'.format(self.dest_port)
        print 'Sequence Number      : {0}'.format(self.sequence)
        print 'Acknowledgement      : {0}'.format(self.acknowledgement)
        print 'TCP header length    : {0}'.format(self.tcph_length)
        print '############ TCP ###########'
        
        return 



def main():

    while True:

        sock = Socket_listing()
        packet = sock.recv_msg()
        ip_header = Ip_header(packet)
        print ip_header.print_ip_header()
        tcp_packet = ip_header.packet[ip_header.iph_length : ip_header.iph_length + 20]
        tcp_header = Tcp_header(tcp_packet)
        print tcp_header.print_tcp_header()
         
        h_size = ip_header.iph_length + tcp_header.tcph_length * 4
        data_size = len(ip_header.packet) - h_size
         
        #get data from the packet
        data = ip_header.packet[h_size:]
         
        print 'Data : ' + data


if __name__ == '__main__':
    main()