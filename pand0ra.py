#Network Traffic URL Extractor
#Add silent/verbose mode for traffic display
#Prompt for manual web or selenium (auto)

from scapy.layers import http
from scapy.all import IP, sniff
import time, urllib, os, stat, sys
from selenium import webdriver

print "Opening webbrowser and navigating to Pandora..."
driver = webdriver.Firefox()				#Opens a Firefox window instance
driver.get("http://www.pandora.com")			#Navigates to Pandora

def process_tcp_packet(packet):				#Displays ip source and method/request
	global desiredURL
	'''
	Processes a TCP packet, and if it contains an HTTP request, it prints it.
	'''
	if not packet.haslayer(http.HTTPRequest):
		# This packet doesn't contain an HTTP request so we skip it
		return
	http_layer = packet.getlayer(http.HTTPRequest)
	ip_layer = packet.getlayer(IP)
	print '\n{0[src]} just requested a {1[Method]} {1[Host]}{1[Path]}'.format(ip_layer.fields, http_layer.fields)	#display logic for print
	if '.com/access/?version' in '{1[Host]}{1[Path]}'.format(ip_layer.fields, http_layer.fields):			#hotwords for hosted media on pandora
		desiredURL='http://'+'{1[Host]}{1[Path]}'.format(ip_layer.fields, http_layer.fields)			#this is the url for the media
		print "\nDownload? (y/n): "										#prompt user for download
		ans = raw_input('')
		print ""
		if ans == "y":
			print "FileName? (no spaces for now please, or escape keys): "					#name file
			nameFile = raw_input('')
			print ""
			#print 'http://'+'{1[Host]}{1[Path]}'.format(ip_layer.fields, http_layer.fields)
			urllib.urlretrieve(desiredURL, os.getcwd()+'/'+str(nameFile)+'.mp3')				#download file
			os.chmod(os.getcwd()+'/'+str(nameFile)+'.mp3', 0o777)						#set permissions for file
		elif ans == "n":
			print "Not Downloading - Moving On..."
		else:
			print "Rerun and enter a proper response (y/n)..."
			sys.exit()
			#continue sniff here
		
# Start sniffing the network.
sniff(filter='tcp', prn=process_tcp_packet)										#sniff process - begin


