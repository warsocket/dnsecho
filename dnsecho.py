#!/usr/bin/env python

#dnsecho
#Copyright (C) 2016  Bram Staps
#
#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU Affero General Public License as
#published by the Free Software Foundation, either version 3 of the
#License, or (at your option) any later version.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU Affero General Public License for more details.
#
#You should have received a copy of the GNU Affero General Public License
#along with this program.  If not, see <http://www.gnu.org/licenses/>.

#TODO
#dropping root
#chroot
#Settings file
#Proper dns ansers for a negative answer


import socket
import struct
import os

# if os.fork():
# 	exit()
# 	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# 	sock.bind(("0.0.0.0", 53))
# else:
sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
sock.bind(("::", 53))

def to_short(num):
	return struct.pack("!H", num)

def from_short(blob):
	return struct.unpack("!H", blob)[0]

QUESTION_OFFSET = 12
def get_dns_reply(data):
	trans_id = data[0:2]
	flags = data[2:4]
	questions = from_short(data[4:6])

	#skip 8 bytes dont care
	offset = QUESTION_OFFSET
	name = []

	#for x in xrange(questions):
	if questions != 1: return #dont aswer when more then 1 qeustion is sent
	while data[offset] != "\x00":
		length = ord(data[offset])
		offset += 1 
		name.append(data[offset:offset+length])
		offset += length

	
	record_type = data[offset+1:offset+3]
	record_class = data[offset+3:offset+5]

	question_end = offset+1+2+2 #include 00 byte + include type + include class


	#reply packet
	pkt = []
	#transaction id field
	pkt.append(trans_id)
	
	#flags field
	ti = from_short(flags)
	ti |= 0x8080 #adds answer and recursion ok bit
	pkt.append(to_short(ti))

	#questions answers auth servers
	pkt.append("\x00\x01") #questions
	pkt.append("\x00\x01") #answer RRs
	pkt.append("\x00\x00") #authority RRs
	pkt.append("\x00\x00") #aditions RRs

 	# original single query
	pkt.append(data[QUESTION_OFFSET:question_end])

	if record_type == "\x00\x01": #ipv4
		#ipv4 answer
		pkt.append("\xC0\x0C") #its pointer (first 2 bits high (C)) pointing to offset 12 (000C) where our only question is https://ask.wireshark.org/questions/50806/help-understanding-dns-packet-data
		pkt.append("\x00\x01") # type: A record
		pkt.append("\x00\x01") # class: IN
		pkt.append("\x00\x00\x0E\x10") # TTL: 3600
		pkt.append("\x00\x04") # datalength 4

		try:
			for i in range(4):
				pkt.append( chr(int(name[i])) )
		except:  #probally not decoding a nume ric ip
			return
		return "".join(pkt)

	elif record_type == "\x00\x1c": #ipv6
		#ipv6 answer
		pkt.append("\xC0\x0C") #its pointer (first 2 bits high (C)) pointing to offset 12 (000C) where our only question is https://ask.wireshark.org/questions/50806/help-understanding-dns-packet-data
		pkt.append("\x00\x1C") # type: AAAA record
		pkt.append("\x00\x01") # class: IN
		pkt.append("\x00\x00\x0E\x10") # TTL: 3600
		pkt.append("\x00\x10") # datalength 16

		def fill4(s):
			while len(s) < 4: #super efficient :P
				s = "0" + s
			return s

		try:
			data = name[0].replace("[", "")
			data = data.replace("]", "")
			data = data.split(":")

			to_insert = 8 - len(data) #calculate missing octets replaced by ::

			if to_insert:
				loc = data.index("")
				for x in xrange(to_insert):
					data.insert(loc, "")
			
			data = map(fill4, data)
			pkt.append( "".join(data).decode("hex") )
			return "".join(pkt)

		except: #if this breaks, useer did boo boo and gets no DNS answer
			return

	elif record_type == "\x00\x06": #SOA
		print "SOA"
		#ipv6 answer
		pkt.append("\xC0\x0C") #its pointer (first 2 bits high (C)) pointing to offset 12 (000C) where our only question is https://ask.wireshark.org/questions/50806/help-understanding-dns-packet-data
		pkt.append("\x00\x06") # type: SOA record
		pkt.append("\x00\x01") # class: IN
		pkt.append("\x00\x00\x0E\x10") # TTL: 3600

		#pkt.append("\x00\x10") # datalength 16
		soa_pkt = []
		soa_pkt.append("\x03dns\x06httpwn\x03org\x00")
		soa_pkt.append("\x00")
		# soa_pkt.append("\x06httpwn\x03org\x00")
		soa_pkt.append("\x00\x00\x00\x00")
		soa_pkt.append("\x00\x00\x0E\x10") # TTL: 3600		
		soa_pkt.append("\x00\x00\x0E\x10") # TTL: 3600
		soa_pkt.append("\x00\x00\x0E\x10") # TTL: 3600
		soa_pkt.append("\x00\x00\x0E\x10") # TTL: 3600

		soa_pkt = "".join(soa_pkt)
		pkt.append(to_short(len(soa_pkt)))
		pkt.append(soa_pkt)
		return "".join(pkt)

	return #no whitelisted record type, no asnwer

while True:
	data, address = sock.recvfrom(0XFFFF)
	if not os.fork():
		# os.c
		reply = get_dns_reply(data)
		if reply: sock.sendto(reply, address)
		exit(0)
