import dpkt
import socket
import struct

filename='test.pcap'
counter=0
ipcounter=0
tcpcounter=0
udpcounter=0
lucky_seq = 0

for ts, pkt in dpkt.pcap.Reader(open(filename,'r')):
    # ts is timestamp
    # pkt is packet content

    counter+=1
    eth = dpkt.ethernet.Ethernet(pkt) 
    if eth.type != dpkt.ethernet.ETH_TYPE_IP:
#        print "not ip pkt", eth.type
        continue

    ip=eth.data
    ipcounter += 1

    if ip.p == dpkt.ip.IP_PROTO_TCP: 
        tcpcounter+=1
#        print "src=", socket.inet_ntoa(ip.src), "dst=", socket.inet_ntoa(ip.dst), "seq=", ip.tcp.seq

    if ip.p == dpkt.ip.IP_PROTO_UDP:
        udpcounter+=1
        if ip.udp.sport==4172 and ip.udp.dport==50002:  #XXX: one-direction
            tmp_lucky_seq = struct.unpack(">I", ip.udp.data[8:12])[0]
            '''
            print "src=", socket.inet_ntoa(ip.src),ip.udp.sport,\
                "dst=", socket.inet_ntoa(ip.dst), ip.udp.dport,\
                "lucky_seq", tmp_lucky_seq
            '''
            #TODO: check seq order
            if lucky_seq == 0:
                lucky_seq = tmp_lucky_seq
                print "First lucky seq", tmp_lucky_seq
            else:
                if lucky_seq != tmp_lucky_seq:
                    print "lost lucky seq from", lucky_seq, "to", tmp_lucky_seq-1
                    lucky_seq = tmp_lucky_seq + 1
                else:
                    lucky_seq += 1
            

print "######################################################"
print "Total number of packets in the pcap file: ", counter
print "Total number of ip packets: ", ipcounter
print "Total number of tcp packets: ", tcpcounter
print "Total number of udp packets: ", udpcounter
