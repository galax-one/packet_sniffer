import scapy.all as scapy
from scapy.layers import http
import sys

args = sys.argv


def sniff_packet(interface):
	print("[SNIFFER] LOG: Capturing start...............")
	scapy.sniff(iface=interface, store=False, prn=on_packet_captured) # Capture the packets and calling a callback functions
	#scapy.sniff(iface=interface, filter="host 127.0.0.1 and port 80", store=False, prn=on_packet_captured) # Example of filter pre-define packets

def on_packet_captured(packet):

    # ---------- Here you can do cool stuff ----------

    # Example 1
	#print(f"PACKET: {packet}\n------------------------------------------------------------------------------\n\n")
	#print(f"PACKET Show: {packet.show()}\n------------------------------------------------------------------------------\n\n")
	#print(f"PACKET Summary: {packet.summary()}\n------------------------------------------------------------------------------\n\n")
			
	# Example 2 :)
	if packet.haslayer(http.HTTPRequest):
		
		url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
		print(f"[SNIFFER] URL REQUEST: {url}")
		
		if packet.haslayer(scapy.Raw):
			print(f"[SNIFFER] POST REQUEST: {packet[scapy.Raw]}")
	
	
if __name__ == "__main__":
	
	if len(args) <= 1:
		print("[SNIFFER] USAGE: python main.py -sniff [interface/adaptor]")
		
	try:
		if args[1] == "-sniff":
			sniff_packet(args[2])
			print("[SNIFFER] LOG: Quitting sniffer...............")
			
	except Exception as e:
		print(f"[SNIFFER] ERROR: {e}")