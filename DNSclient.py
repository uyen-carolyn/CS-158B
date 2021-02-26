"""BASE CODE PROVIDED BY BEN REED"""
import socket
import click
import struct

@click.command()
@click.argument('server')
@click.argument('query')

def resolve(server, query):
	"""
	This will resolve a query given a server IP address.
	If the query looks like an IP address, it will return a domain name.
	If the query looks like a domain name, it will return an IP address. (IPv4 and IPv6 if available)
	Otherwise it will return an error message.
	"""

# SETTING UP SOCKET CONNECTION.
	sd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sd.connect((server, 53))

	flags = 1 << 8
	hdr = struct.pack('!HHHHHH', 17, flags, 1, 0, 0, 0)

	parts = query.split('.')

# IDENTIFY QUERY AS IP ADDRESS OR DOMAIN NAME TO BE RESOLVED.
# IF CONDITION HANDLES IP ADDRESS. 
	if query.replace('.', '').isnumeric():
		parts.reverse()	# kudos to Miamia for explaining the reasoning behind reversing the query
		parts.append("in-addr")
		parts.append("arpa")

		q = b''
		for p in parts:
			q += bytes([len(p)]) + p.encode()

		q+= b'\0\0\x0c\0\1' # kudos to Tye for explaining how changing the question can reverse lookup

		sd.send(hdr+q)
		rsp = sd.recv(1024)

		(id, flags, qcnt, acnt, ncnt, mcnt) = struct.unpack('!HHHHHH', rsp[0:12])

		# VERIFY IF IP ADDRESS EXISTS
		if acnt == 0:	# kudos to Miamia for explaining the meaning of acnt's value at zero
			print("No domain name exists under that address")
		else:

			resolved_domain = rsp[57:len(rsp) - 5].decode()
			resolved_domain += "." + rsp[len(rsp) - 4: len(rsp)].decode()

			r = rsp[-40:]
			for i in range(0, acnt):	# kudos to auk for explaining how formatting byte to ipv4 works
				extracted = r[-4:]	# ip is four values of up to four divided by a period
				rsp_reverse = [str(j) for j in extracted] #since ipv4 is three numbers split between a period
				rsp_reverse = ".".join(rsp_reverse)
				print(" - " + rsp_reverse)
				r = r[:len(r)-16] # to only get ip at the end
# ELSE CONDITION HANDLES DOMAIN NAME.
	else:
		q = b''
		for p in parts:
			q += bytes([len(p)]) + p.encode()

	# RESOLVE TO GET IPV4
		q1 = q + b'\0\0\1\0\1'
		sd.send(hdr+q1)
		rsp_ip_four = sd.recv(1024)
		(id, flags, qcnt, acnt, ncnt, mcnt) = struct.unpack('!HHHHHH', rsp_ip_four[0:12])

		# VERIFY IF DOMAIN EXISTS
		if acnt == 0:
			print("No IPv4 address exist under that domain")

		else:
			print("IPv4 Addresses: ")

			r = list(rsp_ip_four)
			for i in range(0, acnt):	# kudos to Auk for explaining how formatting byte to ipv4 works
				extracted = r[-4:]	# ip is four values of up to three divided by a period
				rsp_four = [str(j) for j in extracted] #since ipv4 is three numbers split between a period
				rsp_four = ".".join(rsp_four)
				print(" - " + rsp_four)
				r = r[:len(r)-16] # to only get ip at the end

	# RESOLVE TO GET IPV6
		q2 = q +  b'\0\0\x1c\0\1'	# kudos to Tye for explaining what they meant by changing the question to get ipv4 vs ipv6
		sd.send(hdr+q2)
		rsp_ip_six = sd.recv(1024)
		(id, flags, qcnt, acnt, ncnt, mcnt) = struct.unpack('!HHHHHH', rsp_ip_six[0:12])

		# VERIFY IF DOMAIN EXISTS
		if acnt == 0:
			print("No IPv6 address exist under that domain")
		else:
			print("IPv6 Addresses: ")

			r = rsp_ip_six.hex()
			for m in range(0, acnt): # kudos to Auk for explaining how formatting byte to ipv6 works
				extracted = r[-32:] # ip is six values of up to four divided by a colon
				rsp_six = ":".join(extracted[n:n+4] for n in range(0,len(extracted), 4)) 	# since ipv6 is four numbers split between a colon
				print(" - " + rsp_six)
				r = r[:len(r)-56] # to only get ip at the end

# ADDED FOR BEST PRACTICE
if __name__ == '__main__':
    resolve()
