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
#chroot (only when we start touching files)
#Proper dns ansers for a negative answer

from settings import settings
import pwd
import socket
import struct
import os

def to_short(num):
	return struct.pack("!H", num)

def from_short(blob):
	return struct.unpack("!H", blob)[0]

def to_dns_levels(s):
	segments = s.split(".")
	if not segments[-1]: segments.pop() #remove (optionsal) trailing dot (post split), make sit possible top enter domian without trailing dot
	segments.append("") # add trailing dot whch wil translate to \x00
	lengths = map(len, segments)
	return "".join(map(lambda x: chr(x[0]) + x[1], zip(lengths, segments)))

def A(name):
	pkt = []
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


def AAAA(name):
	pkt = []
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


def SOA(name):
	pkt = []
	#SOA answer
	pkt.append("\xC0\x0C") #its pointer (first 2 bits high (C)) pointing to offset 12 (000C) where our only question is https://ask.wireshark.org/questions/50806/help-understanding-dns-packet-data
	pkt.append("\x00\x06") # type: SOA record
	pkt.append("\x00\x01") # class: IN
	pkt.append("\x00\x00\x0E\x10") # TTL: 3600

	#pkt.append("\x00\x10") # datalength 16
	soa_pkt = []
	soa_pkt.append(soaname)
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

dns_handlers = {
	"\x00\x01" : A,
	"\x00\x1c" : AAAA,
	"\x00\x06" : SOA,
}

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
	ti |= 0x8400 #adds answer, auth bit
	pkt.append(to_short(ti))

	#questions answers auth servers
	pkt.append("\x00\x01") #questions


	valid = False
	if record_type in dns_handlers:
		ans = dns_handlers[record_type](name)
		if ans:
			#now we have a valid answer
			valid = True

	if valid:
		pkt.append("\x00\x01") #answer RRs
	else:
		pkt.append("\x00\x00") #answer RRs

	pkt.append("\x00\x00") #authority RRs
	pkt.append("\x00\x00") #aditions RRs

 	# original single query
	pkt.append(data[QUESTION_OFFSET:question_end])
			
	if valid: pkt.append(ans) #failure packets are not appended

	return "".join(pkt)

#main starts here

#parsing some settings
ids = pwd.getpwnam(settings["unpriviligeduser"]) #need this before chroot
soaname = to_dns_levels(settings["nameservername"])

sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
sock.bind(("::", 53))

while True:
	data, address = sock.recvfrom(0XFFFF)
	if os.fork(): #parent waits for 1st child
		os.wait()

	else: #child
		if os.fork():
			exit() #gets cleaned by root process
		else: #grandchild
			#drop privileges
			try:
			    os.setgid(ids.pw_gid)
			    os.setuid(ids.pw_uid)
			except:
			    exit() #no lesser priviliges no page

			reply = get_dns_reply(data)
			if reply: sock.sendto(reply, address)
			exit()

		exit()