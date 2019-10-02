import scapy.all as scapy

def get_mac(ip):
	arp_req=scapy.arp(pdst=ip)
	broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
	arp_req_broadcast=broadcast/arp_req
	answer_list=scapy.srp(arp_req_broadcast,timeout=1,verbose=False)[0]
	return answer_list[0][1].hwsrc

def sniff(interface):
	scapy.sniff(iface=interface,store=False,prn=packet_sniff)
	
def packet_sniff(packet):
	if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op ==2:
		try:
			real_mac=get_mac(packet[scapy.ARP].psrc)
			response_mac=packet[scapy.ARP].hwsrc
		
			if real_mac != response_mac :
				print("u r under attack")
		except IndexError:
			pass


sniff("eth0")