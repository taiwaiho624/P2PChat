#!/usr/bin/python3

# Development platform: Ubuntu
# Python version: python3.7
# Version:


from tkinter import *
import sys
import socket
import threading
import time
import datetime
from collections import OrderedDict

#
# Global variables
#
username = ""
my_ip = ""
my_port = ""
joined = False
connected = False
MSID = 0
roomServer_ip = ""
roomServer_port = ""
myroom_name = ""

member_list = {}
socket_list = {}
forward_link = ""

socket_list_lock = threading.Lock()
member_list_lock = threading.Lock()

#
# This is the hash function for generating a unique
# Hash ID for each peer.
# Source: http://www.cse.yorku.ca/~oz/hash.html
#
# Concatenate the peer's username, str(IP address),
# and str(Port) to form a string that be the input
# to this hash function
#
def sdbm_hash(instr):
	hash = 0
	for c in instr:
		hash = int(ord(c)) + (hash << 6) + (hash << 16) - hash
	return hash & 0xffffffffffffffff


#
# Functions to handle user input
#
def send_join_request():
	msg = "J:" + myroom_name + ":" + username +":"+ str(my_ip) + ":" +  str(my_port)+ "::\r\n"
	print("[debug]JOIN request", msg)
	sock.send(msg.encode("ascii"))
	rmsg = sock.recv(2048)
	rmsg = str(rmsg.decode("ascii"))
	print("[debug]JOIN rmsg from server:", rmsg)
	rmsg = rmsg.split(':')
	return rmsg

def updateMemberList(rmsg):
	global MSID
	global joined
	global member_list
	if (rmsg[0]  == 'F'):
		CmdWin.insert(1.0, "\nError retrieving member list, ", rmsg[1])
	else:
		MSID = rmsg[1]
		rmsg = rmsg[2:-2]
		new_member_list = OrderedDict()
		for i,name in enumerate(rmsg[::3]):
			CmdWin.insert(1.0, "\n\t" + name + "\tip: " + rmsg[3*i+1] + ":" + rmsg[3*i+2])
			hashID = str(sdbm_hash(name+rmsg[3*i+1]+rmsg[3*i+2]))
			member_dict = {
				'nickname': name,
				'portnumber' : rmsg[3*i+2],
				'ip' : rmsg[3*i+1],
				'msgid' : 0
			}
			new_member_list[hashID] = member_dict
			if hashID in member_list:
				new_member_list[hashID]['msgid'] = member_list[hashID]['msgid']
		member_list_lock.acquire()
		member_list.clear()
		member_list = new_member_list
		member_list_lock.release()
		current_member_list()


def do_User():
	global username
	entry = userentry.get()
	userentry.delete(0,END)
	if joined:
		CmdWin.insert(1.0, "\nYou cannot change you name after joining a group")
	elif not entry:
		CmdWin.insert(1.0, "\nPlease enter a valid username")
	else:
		outstr = "\n[User] username: "+entry
		username = entry
		CmdWin.insert(1.0, outstr)
		userentry.delete(0, END)

def do_List():
	msg = "L::\r\n"
	sock.send(msg.encode("ascii"))
	rmsg = sock.recv(2048)
	rmsg = str(rmsg.decode("ascii"))
	print("[debug]LIST rmsg from server:", rmsg)
	group_list = rmsg.split(':')
	if group_list[0] == 'F':
		print("Error: ", rmsg)
		CmdWin.insert(1.0, "\nError retrieving member list, ", group_list[1])
	elif len(group_list) <= 3:
		CmdWin.insert(1.0, "\nThere is no any chatroom available.")
	else:
		for i in range(len(group_list)-3):
			CmdWin.insert(1.0, "\n\t"+ group_list[i+1])
		CmdWin.insert(1.0, "\nHere are the active chatrooms:")

def do_Join():
	global username
	global joined
	global member_list
	global MSID
	global myroom_name
	global listen_udp_thread
	global keep_alive_thread
	global listen_tcp_thread
	global start_forward_thread
	entry = userentry.get()
	userentry.delete(0, END)
	if joined:
		CmdWin.insert(1.0, "\nYou have already joined a chatroom")
	elif not entry:
		CmdWin.insert(1.0, "\nPlease enter a chatroom name")
	elif username == "":
		CmdWin.insert(1.0, "\nPlease register a username first")
	else:
		myroom_name = entry
		rmsg = send_join_request()
		if (rmsg[0]  == 'F'):
			CmdWin.insert(1.0, "\nError joining chatroom, ", rmsg[1])
		else:
			updateMemberList(rmsg)
			CmdWin.insert(1.0, "\nMember list:")
			joined = True
		if joined:
			CmdWin.insert(1.0, "\nYou have joined chat room: "+myroom_name)
			keep_alive_thread.start()
			listen_udp_thread.start()
			listen_tcp_thread.start()
			start_forward_thread.start()


def handle_public_tcp_socket():
	print("===Started listening to TCP connection thread===")
	socket_public_tcp = socket.socket()
	socket_public_tcp.bind(("", int(my_port)))
	socket_public_tcp.listen(5)
	while joined:
		try:
			print("[debug][listen to tcp]Accepting incoming TCP connection")
			peer = socket_public_tcp.accept()
			incoming_tcp_thread = threading.Thread(target=handle_incoming_sock ,args=(peer,))
			incoming_tcp_thread.setDaemon(True)
			incoming_tcp_thread.start()
		except Exception as e:
			print("[Error][listen to tcp]Fail to accept connection", e)
			continue
	socket_public_tcp.close()


def handle_incoming_sock(socket, peer=()):
	print("===Started Handling socket connection thread===")
	global socket_list
	global member_list
	global connected
	global forward_link
	broken = False
	conn, addr = socket
	ip, port = addr
	peer_name = ""
	peer_ip = ""
	peer_listening_port = ""
	hashID = ""
	if peer:
		peer_name = peer[0]
		peer_ip = peer[1]
		peer_listening_port = str(peer[2])
		hashID = peer[3]
	while joined:
		print("[debug][connected sockets]Trying to receive message")
		try:
			msg = conn.recv(2048)
		except Exception as e:
			print("[Error][connected sockets]Fail to recv() from peer:",e)
			conn.close()
			break
		else:
			msg = msg.decode("ascii")
			if not msg:
				print("[debug][connected sockets]Connection broken:", addr)
				if hashID:		#in member list
					print("[debug][connected sockets]Lose connection with", peer_name)
					conn.close()
					del socket_list[hashID]
					del member_list[hashID]
					if hashID == forward_link:
						forward_link = ""
						rebuild_forwardlink_thread = threading.Thread(target=startForwardLink)
						rebuild_forwardlink_thread.setDaemon(True)
						rebuild_forwardlink_thread.start()
				else:
					print("[debug][connected sockets]Lose connection with unknown peer")
					conn.close()
				break
			elif msg[0] == 'P':
				print("[debug][connected sockets]Received P2P handshake request:", msg)
				msg = msg.split(":")
				peer_name = msg[2]
				peer_ip = msg[3]
				peer_listening_port = msg[4]
				hashID = str(sdbm_hash(peer_name+peer_ip+peer_listening_port))
				if hashID not in member_list:
					rmsg = send_join_request()
					if rmsg[0] == "F":
						print("[Error][connected sockets]Fail to update member list:", rmsg[1])
						conn.close()
						break
					elif rmsg[0] == "M":
						if rmsg[1] != MSID:
							updateMemberList(rmsg)
							CmdWin.insert(1.0, "\nNew Member list:")
					else:
						print("[debug][connected sockets]Received unknown message format from server:",rmsg)
						conn.close()
						break
				if msg[1] != myroom_name or hashID not in member_list:
					print("[debug][connected sockets]Received message from non-room-member")
					conn.close()
					break
				elif hashID in socket_list:
					print("[debug][connected sockets]Initiating peer already in socket list")
					continue
				else:
					my_hash_id = str(sdbm_hash(username + my_ip + str(my_port)))
					smsg = "S:" + str(member_list[my_hash_id]['msgid']) + "::\r\n"
					try:
						print("[debug][connected sockets]Sending P2P handshake respond message:",smsg)
						conn.send(smsg.encode("ascii"))
					except Exception as e:
						print("[Error][connected sockets]Fail to send P2P respond message:", e)
						conn.close()
						break
					else:
						print("[debug][connected sockets]P2P handshake respond sent")
						connected = True
						member_list_lock.acquire()
						member_list[hashID]['msgid'] = int(msg[5])
						member_list_lock.release()
						socket_list_lock.acquire()
						socket_list[hashID] = conn
						socket_list_lock.release()
						current_member_list()
						current_socket_list()
			elif msg[0] == "T":
				receive_msg(msg, peer_name, hashID)
			else:
				print("[Error][connected sockets]Received unknown message format:", msg)
				if hashID:		#in member list
					conn.close()
					del socket_list[hashID]
					del member_list[hashID]
					if hashID == forward_link:
						forward_link = ""
						rebuild_forwardlink_thread = threading.Thread(target=startForwardLink)
						rebuild_forwardlink_thread.setDaemon(True)
						rebuild_forwardlink_thread.start()
				conn.close()
				break

def startForwardLink():
	print("\n===Started establishing forward link===")
	global MSID
	global member_list
	global socket_list
	global connected
	global forward_link
	my_hash_id = str(sdbm_hash(username + my_ip + str(my_port)))
	start = int()
	gList = member_list
	gList = sorted(gList.keys())
	my_index = gList.index(str(my_hash_id))
	start = (my_index + 1) % len(gList)
	time.sleep((my_index + 1)/len(gList) * 5)
	if not forward_link:
		print("[debug][ForwardLink]Trying to establish forward link...")
		while gList[start] != my_hash_id:
			if gList[start] in socket_list:
				start = (start + 1) % len(gList)
				continue
			else:
				try:
					sock_forward = socket.socket()
					sock_forward.connect((member_list[gList[start]]['ip'], int(member_list[gList[start]]['portnumber'])))
					print ("[debug][ForwardLink]Sucessful TCP connection with forward link member", member_list[gList[start]]['nickname'])
				except Exception as e:
					print("[Error][ForwardLink]Fail to connect with forward link member:", e)
					start = (start + 1) % len(gList)
					sock_forward.close()
					continue
				else:
					msg = 'P:' + myroom_name + ':' + username + ':' + str(my_ip) + ':' + str(my_port) + ':' + str(member_list[my_hash_id]['msgid']) + '::\r\n'
					print("[debug][ForwardLink]Sending P2P handshake request msg:", msg)
					sock_forward.send(msg.encode("ascii"))
					try:
						rmsg = sock_forward.recv(200)
						print("[debug][ForwardLink]Received P2P respond message:", rmsg)
					except Exception as e:
						print("[Error][ForwardLink]Fail to recv() from forward link member:", e)
						start = (start + 1) % len(gList)
						sock_forward.close()
						continue
					else:
						rmsg = rmsg.decode("ascii")
						rmsg = rmsg.split(':')
						if rmsg[0] == 'S':
							connected = True
							forward_link = gList[start]
							socket_list_lock.acquire()
							socket_list[gList[start]] = sock_forward
							socket_list_lock.release()
							member_list_lock.acquire()
							member_list[gList[start]]['msgid'] = int(rmsg[1])
							member_list_lock.release()

							CmdWin.insert(1.0, "\nsucessfully establish a forward link to " + member_list[gList[start]]['nickname'])
							print("[debug][ForwardLink]Forward link successfully established with", member_list[gList[start]]['nickname'])
							current_member_list()
							current_socket_list()

							peer_sock = (sock_forward, (member_list[gList[start]]['ip'],int(member_list[gList[start]]['portnumber'])))
							peer = (member_list[gList[start]]['nickname'], member_list[gList[start]]['ip'], member_list[gList[start]]['portnumber'], gList[start])
							forward_link_thread = threading.Thread(target=handle_incoming_sock, args=(peer_sock, peer, ))
							forward_link_thread.setDaemon(True)
							forward_link_thread.start()
							return
						else:
							print("[debug][ForwardLink]Received unknown message format:", rmsg)
							start = (start + 1) % len(gList)
							sock_forward.close()
							continue
		print("[Error][ForwardLink]Fail to establish forward link")#, retrying in 5s")
		"""time.sleep(5)
		gList = member_list
		gList = sorted(gList.keys())
		my_index = gList.index(str(my_hash_id))
		start = (my_index + 1) % len(gList)"""

def current_member_list():
	print("\n[debug]Current member list:")
	for hashID, member_dict in member_list.items():
		print("\t["+hashID+"]", member_dict)

def current_socket_list():
	print("\n[debug]Current socket list:")
	for hashID, sock in socket_list.items():
		print("\t["+member_list[hashID]['nickname']+"] "+"["+hashID+"]", sock)

def keepAlive():
	print("\n===Started keepAlive thread===")
	global member_list
	global MSID
	while sock:
		time.sleep(20)
		if joined:
			print("[debug]Keeping alive...")
			rmsg = send_join_request()
			if (rmsg[0]  == 'F'):
				CmdWin.insert(1.0, "\nError keeping connection with server alive: ", rmsg[1], "retrying in 20s.")
			else:
				new_MSID = rmsg[1]
				if new_MSID == MSID:
					pass
				else:
					updateMemberList(rmsg)
					CmdWin.insert(1.0, "\nNew Member list:")
		if not forward_link:
			rebuild_forwardlink_thread = threading.Thread(target=startForwardLink)
			rebuild_forwardlink_thread.setDaemon(True)
			rebuild_forwardlink_thread.start()


def forward_msg(raw_msg, ignore=[]):
	msg = raw_msg.encode("ascii")
	if not ignore:
		for hashID, sock in socket_list.items():
			sock.send(msg)
	else:
		for hashID, sock in socket_list.items():
			if hashID in ignore:
				continue
			else:
				sock.send(msg)

def receive_msg(msg, sender, senderHID):
	global member_list
	print("[debug][TEXT message]Received message from", sender+":", msg)
	raw_msg = msg
	rmsg = msg.split(':')
	roomname = rmsg[1]
	originHID = rmsg[2]
	origin_username = rmsg[3]
	msgID = rmsg[4]
	msgLength = rmsg[5]
	message_content = rmsg[6:-2]
	message_content = ":".join(message_content)
	if roomname != myroom_name:
		print("[Error][TEXT message]Received message from outside this room:", rmsg[1])
		return
	elif originHID not in member_list:
		jmsg = send_join_request()
		if jmsg[0] == "F":
			print("[debug][TEXT message]Fail to update member list", jmsg[1])
			return
		elif jmsg[0] == "M":
			if jmsg[1] == MSID:
				print("[Error][TEXT message]Received message from unknown peer:", origin_username)
				return
			else:
				updateMemberList(jmsg)
				CmdWin.insert(1.0, "\nNew Member list:")
				if originHID in member_list:
					member_list_lock.acquire()
					member_list[originHID]['msgid'] = int(msgID)
					member_list_lock.release()
					MsgWin.insert(1.0, "\n["+origin_username+"] "+message_content)
					forward_msg(raw_msg, ignore=[senderHID, originHID])
				else:
					print("[Error][TEXT message]Received message from unknown peer:", origin_username)
					return
	elif int(msgID) <= member_list[originHID]['msgid']:
		print("[debug][TEXT message]Received duplicate message from", origin_username)
		return
	else:
		member_list_lock.acquire()
		member_list[originHID]['msgid'] = int(msgID)
		member_list_lock.release()
		MsgWin.insert(1.0, "\n["+origin_username+"] "+message_content)
		forward_msg(raw_msg, ignore=[senderHID, originHID])

def do_Send():
	global member_list
	entry = userentry.get()
	userentry.delete(0,END)
	if not entry:
		pass
	elif not joined:
		CmdWin.insert(1.0, "\nYou have not joined a chatroom")
	elif not connected:
		message_content = entry
		MsgWin.insert(1.0, "\n["+username+"] "+message_content)
	else:
		message_content = entry
		MsgWin.insert(1.0, "\n["+username+"] "+message_content)
		msgLength = len(message_content)
		my_hash_id = str(sdbm_hash(username+my_ip+str(my_port)))
		member_list_lock.acquire()
		member_list[my_hash_id]['msgid'] += 1
		member_list_lock.release()
		raw_msg = "T:"+myroom_name+":"+my_hash_id+":"+username+":"+str(member_list[my_hash_id]['msgid'])+":"+str(msgLength)+":"+message_content+"::\r\n"
		print("[debug]SEND:", raw_msg)
		forward_msg(raw_msg)

def check_exist(entry,member_list):
	for key , value in member_list:
		if value['nickname'] == entry:
			return True
	return False

def do_Poke():
	rmsg = send_join_request()
	if rmsg[0] == "F":
		print("[debug][POKE]Fail to update member list")
	elif rmsg[0] == "M":
		if rmsg[1] != MSID:
			updateMemberList(rmsg)
	try:
		sock_udp_sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	except socket.error as e:
		print("Socket error: ", e)
		return
	if (joined==True):
		entry = userentry.get()
		if not entry:
			for hashID, member_dict in member_list.items():
				CmdWin.insert(1.0, "\n\t" + member_dict['nickname'])
			CmdWin.insert(1.0, "\nHere are the nicknames of the member in the chat room:")
			CmdWin.insert(1.0, "\nTo Whom you want to send the poke" )
		elif entry==username:
			CmdWin.insert(1.0, "\nYou have entered yourself name , please enter another name")
		elif (check_exist(entry,member_list.items()) == False):
			CmdWin.insert(1.0, "\nThere is no such a person")
		else:
			receiver_ip=""
			receiver_port=""
			for key , value in member_list.items():
				if value['nickname'] == entry:
					receiver_ip = value['ip']
					receiver_port = value['portnumber']
			receiver_address =  (receiver_ip,int(receiver_port))
			msg = "K:" + myroom_name + ":" + username +"::\r\n"
			threading.Thread(target=sendPokeMsg , args=(msg,receiver_address,sock_udp_sender)).start()
		userentry.delete(0, END)
	else:
		CmdWin.insert(1.0, "\nYou have not joined any chatroom yet")

def sendPokeMsg(msg ,receiver_address, sock_udp_sender):
	print ("started sendPokeMsg thread")
	sock_udp_sender.sendto(msg.encode("ascii"),receiver_address)
	sock_udp_sender.settimeout(10)
	try:
		data,addr = sock_udp_sender.recvfrom(2048)
		CmdWin.insert(1.0, "\nsuccesfully received ACK ")
	except:
		CmdWin.insert(1.0, "\n2 seconds has passed,no ACK has been received ")

def handle_udp_socket():
	print("started handle_udp_socket")
	global sock_udp

	while joined:
		try:
			data, addr = sock_udp.recvfrom(200)
			data = data.decode("ascii")
			print("[debug]handle_udp_socket rmsg from peer:", data)
			rmsg = data.split(":")
			if data[0] == "K":
				if rmsg[1] == myroom_name:
					MsgWin.insert(1.0, "\nReceived Poke message From " + rmsg[2])
					msg = "A::\r\n"
					sock_udp.sendto(msg.encode("ascii"),addr)
		except:
			continue
	sock_udp.close()

def do_Quit():
	global joined
	global connected
	global sock
	global sock_udp
	global socket_list
	connected = False
	joined = False
	print("[debug]closing sockets...")
	for hashID, peer_sock in socket_list.items():
		print("[debug]closing socket", hashID)
		peer_sock.close()
	sock.close()
	sock_udp.close()
	sys.exit(0)



#
# Set up of Basic UI
#
win = Tk()
win.title("MyP2PChat")

#Top Frame for Message display
topframe = Frame(win, relief=RAISED, borderwidth=1)
topframe.pack(fill=BOTH, expand=True)
topscroll = Scrollbar(topframe)
MsgWin = Text(topframe, height='15', padx=5, pady=5, fg="red", exportselection=0, insertofftime=0)
MsgWin.pack(side=LEFT, fill=BOTH, expand=True)
topscroll.pack(side=RIGHT, fill=Y, expand=True)
MsgWin.config(yscrollcommand=topscroll.set)
topscroll.config(command=MsgWin.yview)

#Top Middle Frame for buttons
topmidframe = Frame(win, relief=RAISED, borderwidth=1)
topmidframe.pack(fill=X, expand=True)
Butt01 = Button(topmidframe, width='6', relief=RAISED, text="User", command=do_User)
Butt01.pack(side=LEFT, padx=8, pady=8);
Butt02 = Button(topmidframe, width='6', relief=RAISED, text="List", command=do_List)
Butt02.pack(side=LEFT, padx=8, pady=8);
Butt03 = Button(topmidframe, width='6', relief=RAISED, text="Join", command=do_Join)
Butt03.pack(side=LEFT, padx=8, pady=8);
Butt04 = Button(topmidframe, width='6', relief=RAISED, text="Send", command=do_Send)
Butt04.pack(side=LEFT, padx=8, pady=8);
Butt06 = Button(topmidframe, width='6', relief=RAISED, text="Poke", command=do_Poke)
Butt06.pack(side=LEFT, padx=8, pady=8);
Butt05 = Button(topmidframe, width='6', relief=RAISED, text="Quit", command=do_Quit)
Butt05.pack(side=LEFT, padx=8, pady=8);

#Lower Middle Frame for User input
lowmidframe = Frame(win, relief=RAISED, borderwidth=1)
lowmidframe.pack(fill=X, expand=True)
userentry = Entry(lowmidframe, fg="blue")
userentry.pack(fill=X, padx=4, pady=4, expand=True)

#Bottom Frame for displaying action info
bottframe = Frame(win, relief=RAISED, borderwidth=1)
bottframe.pack(fill=BOTH, expand=True)
bottscroll = Scrollbar(bottframe)
CmdWin = Text(bottframe, height='15', padx=5, pady=5, exportselection=0, insertofftime=0)
CmdWin.pack(side=LEFT, fill=BOTH, expand=True)
bottscroll.pack(side=RIGHT, fill=Y, expand=True)
CmdWin.config(yscrollcommand=bottscroll.set)
bottscroll.config(command=CmdWin.yview)

#for keeping the connection alive
keep_alive_thread = threading.Thread(target=keepAlive)
keep_alive_thread.setDaemon(True)
#for receving message from Peer through UDP
listen_udp_thread = threading.Thread(target=handle_udp_socket)
listen_udp_thread.setDaemon(True)
#for receving message from Peer through TCP
listen_tcp_thread = threading.Thread(target=handle_public_tcp_socket)
listen_tcp_thread.setDaemon(True)
#for sending a forward link
start_forward_thread = threading.Thread(target=startForwardLink)
start_forward_thread.setDaemon(True)

def main():
	if len(sys.argv) != 4:
		print("P2PChat.py <server address> <server port no.> <my port no.>")
		sys.exit(2)

	global roomServer_ip
	global roomServer_port
	global my_port
	global my_ip
	global sock
	global sock_udp
	roomServer_ip = sys.argv[1]
	roomServer_port = sys.argv[2]
	my_port = sys.argv[3]
	try:
		sock = socket.socket()
		sock.connect((roomServer_ip, int(roomServer_port)))
		my_ip = sock.getsockname()[0]
		CmdWin.insert(1.0, "\nConnected to room server sucessfully")
		print("[debug]Connection established with server: ", roomServer_ip+":"+roomServer_port)
	except socket.error as e:
		print("Socket error: ", e)
		sys.exit(1)
	try:
		sock_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		sock_udp.bind(("",int(my_port)))
	except socket.error as e:
		print("Socket error: ", e)
		sys.exit(1)
	win.mainloop()

if __name__ == "__main__":
	main()
