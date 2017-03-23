from __future__ import print_function
from twisted.internet.protocol import DatagramProtocol
import logging

import socket
from random import random
from crypto import ECCrypto
from netifaces import AF_INET, AF_INET6, AF_LINK, AF_PACKET, AF_BRIDGE
import netifaces
from struct import unpack_from
from socket import inet_ntoa, inet_aton
from Wcandidate import Wcandidate
from WcandidateGroup import WcandidateGroup
from twisted.internet import task
from twisted.internet import reactor
from struct import pack, unpack_from, Struct
import Message
import threading
logging.basicConfig(level=logging.DEBUG, filename="logfile", filemode="a+",
                    format="%(asctime)-15s %(levelname)-8s %(message)s")
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

import os
import sys
if sys.platform == "darwin":
    # Workaround for annoying MacOS Sierra bug: https://bugs.python.org/issue27126
    # As fix, we are using pysqlite2 so we can supply our own version of sqlite3.
    import pysqlite2.dbapi2 as sqlite3
else:
    import sqlite3

#now the walker inherits twisted.DatagramProtocol, which is driven by twisted reactor
#no need to touch socket anymore, can use Protocol.transport to send packet and datagramReceived() for listening
#Whenever you creates a walker instance, it calls startProtocol() (it is a built-in function of twisted.Protocol)
#startProtocol() initiates the looping call of take_step, which will send introduction request every 5 seconds.
#datagramReceived() will keep lisening on the port and call decode_message to handle messages
#functions named as on_XXXX is message handler for a specific message type.
#functions like encode_xxxx is the encoder of a specific message type, which convert message instances to binary string
#functions like decode_xxxx is the decoder of a specific message type, which convert binary string to certain message instances.
class Walker(DatagramProtocol):

    def __init__(self,port = 25000,is_tracker=False):
        #super(Walker, self).__init__():
        #tracker_ADDR is reserved for convenience of testing
        #self.tracker_ADDR = [
        #(u"127.0.0.1"     ,1235),
        #(u"130.161.119.206"      , 6421),
        #(u"130.161.119.206"      , 6422),
        #(u"131.180.27.155"       , 6423),
        #(u"83.149.70.6"          , 6424),
        #(u"95.211.155.142"       , 6427),
        #(u"95.211.155.131"       , 6428),
        #]
        #how many times other candidates walk to you, only for load balancing experiment use
        self.visited_count=0
        self.loop_count = 0
        self.is_tracker=is_tracker
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        #get the network interface which connected to public Internet (8.8.8.8,8) is the root DNS server
        #so that the network interface connected to it is guranteed to be connected to public Internet
        self.lan_ip = self.get_lan_IP(("8.8.8.8",8))
        self.lan_port = port
        self.lan_netmask = self.get_netmask(self.lan_ip)
        self.lan_addr = (self.lan_ip,self.lan_port)
        #we have no knowledge for our wan IP for now.
        self.wan_ip = "0.0.0.0"
        self.wan_port =0
        self.wan_addr = ("0.0.0.0",0)
        #self.sock.bind(self.lan_addr)

        #indicates the current wan IP vote contains only 0.0.0.0 and the voter is nothing (empty list)
        #self.WAN_VOTE = {"0.0.0.0:0":[]}
        self.WAN_VOTE = dict()
        self.candidate_group =WcandidateGroup()
        self._global_time=1

        self._struct_B = Struct(">B")
        self._struct_BBH = Struct(">BBH")
        self._struct_BH = Struct(">BH")
        self._struct_H = Struct(">H")
        self._struct_HH = Struct(">HH")
        self._struct_LL = Struct(">LL")
        self._struct_Q = Struct(">Q")
        self._struct_QH = Struct(">QH")
        self._struct_QL = Struct(">QL")
        self._struct_QQHHBH = Struct(">QQHHBH")
        self._struct_ccB = Struct(">ccB")
        self._struct_4SH = Struct(">4sH")
    #(u"dispersy4.st.tudelft.nl", 6424),
        self._encode_message_map = dict()  # message.name : EncodeFunctions
        self._decode_message_map = dict()  # byte : DecodeFunctions

        # the dispersy-introduction-request and dispersy-introduction-response have several bitfield
        # flags that must be set correctly
        # reserve 1st bit for enable/disable advice
        self._encode_advice_map = {True: int("1", 2), False: int("0", 2)}
        self._decode_advice_map = dict((value, key) for key, value in self._encode_advice_map.iteritems())
        # reserve 2nd bit for enable/disable sync
        self._encode_sync_map = {True: int("10", 2), False: int("00", 2)}
        self._decode_sync_map = dict((value, key) for key, value in self._encode_sync_map.iteritems())
        # reserve 3rd bit for enable/disable tunnel (02/05/12)
        self._encode_tunnel_map = {True: int("100", 2), False: int("000", 2)}
        self._decode_tunnel_map = dict((value, key) for key, value in self._encode_tunnel_map.iteritems())
        # 4th, 5th and 6th bits are currently unused
        # reserve 7th and 8th bits for connection type
        self._encode_connection_type_map = {u"unknown": int("00000000", 2), u"public": int("10000000", 2), u"symmetric-NAT": int("11000000", 2)}
        self._decode_connection_type_map = dict((value, key) for key, value in self._encode_connection_type_map.iteritems())
        #this is the master-key for multichain community
        self.master_key = "3081a7301006072a8648ce3d020106052b81040027038192000407afa96c83660dccfbf02a45b68f4bc" + \
                     "4957539860a3fe1ad4a18ccbfc2a60af1174e1f5395a7917285d09ab67c3d80c56caf5396fc5b231d84ceac23627" + \
                     "930b4c35cbfce63a49805030dabbe9b5302a966b80eefd7003a0567c65ccec5ecde46520cfe1875b1187d469823d" + \
                     "221417684093f63c33a8ff656331898e4bc853bcfaac49bc0b2a99028195b7c7dca0aea65"
        self.master_key_hex = self.master_key.decode("HEX")

        self.crypto = ECCrypto()
        self.ec = self.crypto.generate_key(u"medium")
        self.key = self.crypto.key_from_public_bin(self.master_key_hex)
        self.mid = self.crypto.key_to_hash(self.key.pub())
        #the dispersy vesion and community version of multichain community version of multichain community in the tracker
        self.dispersy_version = "\x00"
        self.community_version = "\x01"
        #print ord(self.community_version)
        #create my key in multichain community, and convert it to mid for signiture use
        self.prefix = self.dispersy_version+self.community_version+self.mid
        self.my_key = self.crypto.generate_key(u"medium")
        self.my_mid = self.crypto.key_to_hash(self.my_key.pub())
        self.my_public_key = self.crypto.key_to_bin(self.my_key.pub())
        #print len(self.my_mid)
        #get my lan_IP
        #self.lan_ip = self.get_lan_IP()
        #self.lan_port = 32000
        #self.lan_addr = (self.lan_ip,self.lan_port)
        #print self.lan_addr
        #this is similar to the container in conversion.encode_message()
        self.container = [self.prefix,chr(246)]
        self.reactor = reactor
        self.listening_port=self.reactor.listenUDP(self.lan_port, self)


    def startProtocol(self):
        print("protocol started")
        if(self.is_tracker==False):
            loop = task.LoopingCall(self.take_step)
            loop.start(5.0)
            #loop_c = task.LoopingCall(self.loop_counting)
            #loop_c.start(10)

    def stopProtocol(self):
        conn  = sqlite3.connect('load_balancing.db')
        cur =  conn.cursor()
        sql = ''' UPDATE visit
                  SET min1 = ? ,
                  min2 = ? ,
                  min3 = ? ,
                  min4 = ? ,
                  min5 = ? 
                  WHERE walker = ?'''
        data = (self.visited_count,self.visited_count,self.visited_count,self.visited_count,self.visited_count,self.lan_port)
        cur.execute(sql,data)
        conn.commit()
        conn.close()

    def loop_counting(self):
        self.loop_count = self.loop_count+1
        if(self.loop_count>5):
            #self.transport.loseConnection()
            reactor.stop()


    #take one step
    def take_step(self):
        print ("walker "+str(self.lan_port)+" take step#################")
        candidate_to_walk = self.get_candidate_to_walk()
        #print candidate_to_walk
        candidate_to_walk_ADDR = candidate_to_walk.get_WAN_ADDR()
        #message_puncture_request = self.create_puncture_request(("8.8.8.8",8),("8.8.8.8",8))
        message_introduction_request = self.create_introduction_request(candidate_to_walk_ADDR,self.lan_addr,self.lan_addr)
        #message_puncture_request = self.create_puncture_request(("8.8.8.8",8),("8.8.8.8",8))

        #self.sock.sendto(message_introduction_request.packet,candidate_to_walk_ADDR)
        self.transport.write(message_introduction_request.packet,candidate_to_walk_ADDR)
        #self.transport.write(message_puncture_request.packet,candidate_to_walk_ADDR)
        logger.info("take step to: "+str(candidate_to_walk_ADDR))

    #a bunch of message creator
    def create_introduction_request(self,destination_address,source_lan_address,source_wan_address):
        identifier = int(random() * 2 ** 16)
        data = [inet_aton(destination_address[0]), self._struct_H.pack(destination_address[1]),
                inet_aton(source_lan_address[0]), self._struct_H.pack(source_lan_address[1]),
                inet_aton(source_wan_address[0]), self._struct_H.pack(source_wan_address[1]),
                self._struct_B.pack(self._encode_advice_map[True] | self._encode_connection_type_map[u"unknown"] | self._encode_sync_map[False]),
                self._struct_H.pack(identifier)]
        container = [self.prefix,chr(246)]
        #container.append(self.my_mid)
        my_public_key = self.my_public_key
        #container.extend((self._struct_H.pack(len(my_public_key)), my_public_key))
        container.append(self.my_mid)
        #now = int(time())
        now = self._struct_Q.pack(self._global_time)
        container.append(now)
        container.extend(data)
        #print container
        packet = "".join(container)
        #print ("the packet length is: "+str(len(packet)))
        signiture = self.crypto.create_signature(self.my_key, packet)
        #print ("the signiture length is: "+str(len(signiture)))
        packet = packet + signiture
        #print repr(signiture)
        #message = Message.introduction_request()
        #message.destination_addr = destination_address
        #message.sender_lan_addr = source_lan_address
        #message.sender_wan_addr = source_wan_address
        #message.identifier = identifier
        #message.mid = self.my_mid
        #message.global_time = now
        #message.signiture = signiture
        #message.message_type = 246
        #message.prefix = self.prefix
        #message.packet = packet
        self.visited_count= self.visited_count+1

        message=Message.message(destination_address=destination_address,source_lan_address=source_lan_address,source_wan_address=source_wan_address,identifier=identifier,
                                mid=self.mid,global_time=now,signiture=signiture,message_type=246,prefix=self.prefix,packet=packet)
        return message
    def create_introduction_response(self,identifier,destination_address,source_lan_address,source_wan_address,lan_introduction_address,wan_introduction_address):
        data = (inet_aton(destination_address[0]), self._struct_H.pack(destination_address[1]),
                inet_aton(source_lan_address[0]), self._struct_H.pack(source_lan_address[1]),
                inet_aton(source_wan_address[0]), self._struct_H.pack(source_wan_address[1]),
                inet_aton(lan_introduction_address[0]), self._struct_H.pack(lan_introduction_address[1]),
                inet_aton(wan_introduction_address[0]), self._struct_H.pack(wan_introduction_address[1]),
                self._struct_B.pack(self._encode_connection_type_map[u"unknown"] | self._encode_tunnel_map[False]),
                self._struct_H.pack(identifier))
        container = [self.prefix,chr(245)]
        container.append(self.my_mid)
        now = self._struct_Q.pack(self._global_time)
        container.append(now)
        container.extend(data)
        packet = "".join(container)
        signiture = self.crypto.create_signature(self.my_key, packet)
        packet = packet + signiture

        #message = Message.introduction_response()
        #message.destination_addr = destination_address
        #message.sender_lan_addr = source_lan_address
        #message.sender_wan_addr = source_wan_address
        #message.lan_introducted_addr = lan_introduction_address
        #message.wan_introducted_addr = wan_introduction_address
        #message.identifier = identifier
        #message.mid = self.my_mid
        #message.global_time = now
        #message.signiture = signiture
        #message.message_type = 246
        #message.prefix = self.prefix
        #message.packet = packet

        message = Message.message(destination_address=destination_address,source_lan_address=source_lan_address,source_wan_address=source_wan_address,lan_introduction_address=lan_introduction_address,
                                  wan_introduction_address=wan_introduction_address,identifier=identifier,mid=self.mid,global_time=now,signiture=signiture,message_type=245,prefix=self.prefix,packet=packet)
        return message
    def create_puncture_request(self,lan_walker_address,wan_walker_address):
        identifier = int(random() * 2 ** 16)
        data = (inet_aton(lan_walker_address[0]), self._struct_H.pack(lan_walker_address[1]),
                inet_aton(wan_walker_address[0]), self._struct_H.pack(wan_walker_address[1]),
                self._struct_H.pack(identifier))
        container = [self.prefix,chr(250)]
        #my_public_key = self.my_public_key
        now = self._struct_Q.pack(self._global_time)
        container.append(now)
        container.extend(data)
        #print container
        packet = "".join(container)
        #since it uses NoAuthentication, the signiture is ""
        signiture =""
        packet = packet+signiture

        #message = Message.puncture_request()
        #message.lan_walker_addr = lan_walker_addr
        #message.wan_walker_addr = wan_walker_addr
        #message.identifier = identifier
        #message.mid = self.my_mid
        #message.global_time = now
        #message.signiture = signiture
        #message.message_type = 250
        #message.prefix = self.prefix
        #message.packet = packet

        message=Message.message(lan_walker_address=lan_walker_address,wan_walker_address=wan_walker_address,identifier=identifier,mid=self.mid,global_time=now,
                                signiture=signiture,message_type=250,prefix=self.prefix,packet=packet)
        return message

    def create_puncture(self,identifier,source_lan_address,source_wan_address):
        #the identifier of dispersy-puncture should be same to corresponding puncture-request
        #but since this is only an experiment, so be it...
        assert isinstance(source_lan_address,tuple),source_lan_address
        assert isinstance(source_wan_address,tuple),source_wan_address
        data = (inet_aton(source_lan_address[0]), self._struct_H.pack(source_lan_address[1]),
                inet_aton(source_wan_address[0]), self._struct_H.pack(source_wan_address[1]),
                self._struct_H.pack(identifier))
        container = [self.prefix,chr(249)]
        container.append(self.my_mid)
        now = self._struct_Q.pack(self._global_time)
        container.append(now)
        container.extend(data)
        packet = "".join(container)
        signiture = self.crypto.create_signature(self.my_key, packet)
        packet = packet + signiture

        #message = Message.puncture()
        #message.sender_lan_addr = source_lan_address
        #message.sender_wan_addr = source_wan_address
        #message.identifier = identifier
        #message.mid = self.my_mid
        #message.global_time = now
        #message.signiture = signiture
        #message.message_type = 250
        #message.prefix = self.prefix
        #message.packet = packet

        message = Message.message(source_lan_address=source_lan_address,source_wan_address=source_wan_address,identifier=identifier,
                                  mid=self.mid,global_time=now,signiture=signiture,message_type=249,prefix=self.prefix,packet=packet)
        return message

    def create_identity(self):
        identifier = int(random() * 2 ** 16)
        container = [self.prefix,chr(248)]
        #container.append(self.my_mid)
        #for dispersy-identity, it always uses "bin" as encoding
        #regardless of community-version
        my_public_key = self.my_public_key
        container.extend((self._struct_H.pack(len(my_public_key)), my_public_key))
        #now = int(time())
        #global_time = (self._global_time,0)
        #print "global time tuple is: "+str(global_time)
        #print type(global_time)
        now = self._struct_Q.pack(self._global_time)
        container.append(now)
        data=()
        container.extend(data)
        #print container
        packet = "".join(container)
        signiture = self.crypto.create_signature(self.my_key, packet)
        packet = packet+signiture

        #message = Message.identity()
        #message.identifier = identifier
        #message.mid = self.my_mid
        #message.global_time = now
        #message.signiture = signiture
        #message.message_type = 248
        #message.prefix = self.prefix
        #message.packet = packet

        message=Message.message(identifier=identifier,mid=self.mid,global_time=now,signiture=signiture,message_type=248,prefix=self.prefix,packet=packet)
        return message


    def datagramReceived(self, data, addr):
        #print("received %r from %s" % (data, addr))
        print("received data from" +str(addr))
        #now we receive a UDP datagram, call decode_message to decode it
        self.decode_message(data,addr)
        #self.transport.write(data, addr)

    def decode_message(self,packet,addr):
        message_id = ord(packet[22])
        logger.info("message id is:"+str(message_id))
        print("message id is:"+str(message_id))
        if message_id == 247:
            print("here is a missing-identity message")
            #placeholder = PlaceHolder(23)
            self.on_missing_identity(packet,addr)
        if message_id == 245:
            print("here is a introduction-response")
            #placeholder = PlaceHolder(23)
            self.on_introduction_response(packet,addr)
        if message_id == 246:
            print("here is a introduction-request")
            #placeholder = PlaceHolder(23)
            self.on_introduction_request(packet,addr)
        if message_id == 250:
            print("here is a puncture request")
            #placeholder = PlaceHolder(23)
            self.on_puncture_request(packet,addr)
        if message_id == 249:
            print("here is a puncture")

    # a bunch of message handler
    def on_introduction_request(self,packet,addr):
        #placeholder = PlaceHolder(23)
        message_request = self.decode_introduction_request(packet)
        stumble_candidate = Wcandidate(message_request.source_lan_address,addr)
        self.candidate_group.add_candidate_to_stumble_list(stumble_candidate)
        #do wan_vote
        self.wan_address_vote(message_request.destination_address,addr)
        #we don't have codes to determine whether the candidate is within our lan, so we use wan address.
        candidate_request = Wcandidate(message_request.source_lan_address,message_request.source_wan_address)
        candidate_to_introduce = self.candidate_group.get_candidate_to_introduce(candidate_request)
        if candidate_to_introduce!=None:
            introduced_lan_addr = candidate_to_introduce.get_LAN_ADDR()
            introduced_wan_addr = candidate_to_introduce.get_WAN_ADDR()
        else:
            introduced_lan_addr=("0.0.0.0",0)
            introduced_wan_addr=("0.0.0.0",0)
        message_response = self.create_introduction_response(message_request.identifier,addr,self.lan_addr,self.lan_addr,introduced_lan_addr,introduced_wan_addr)
        #now it is time to create puncture request
        if candidate_to_introduce!=None:
            message_puncture_request = self.create_puncture_request(message_request.source_lan_address,message_request.source_lan_address)
            self.transport.write(message_puncture_request.packet,candidate_to_introduce.get_WAN_ADDR())
            self.transport.write(message_puncture_request.packet,candidate_to_introduce.get_LAN_ADDR())
        self.transport.write(message_response.packet,addr)
    def on_introduction_response(self,packet,addr):
        #placeholder = PlaceHolder(23)
        message = self.decode_introduction_response(packet)
        self.wan_address_vote(message.destination_address,addr)
        walk_candidate=Wcandidate(message.source_lan_address,addr)
        self.candidate_group.add_candidate_to_walk_list(walk_candidate)
        print("the introduced candidate is: "+ str(message.wan_introduction_address))
        if message.lan_introduction_address!=("0.0.0.0",0) and message.wan_introduction_address!=("0.0.0.0",0):
            introduced_candidate = Wcandidate(message.lan_introduction_address,message.wan_introduction_address)
            self.candidate_group.add_candidate_to_intro_list(introduced_candidate)
            print("new candidate has been added to intro list")
    def on_puncture_request(self,packet,addr):
        #placeholder = PlaceHolder(23)
        message_puncture_request = self.decode_puncture_request(packet)
        lan_walker_address = message_puncture_request.lan_walker_address
        wan_walker_address = message_puncture_request.wan_walker_address
        self.wan_addr = self.get_majority_vote()
        print("the wan addr from majority vote is:")
        print(self.wan_addr)
        message_puncture = self.create_puncture(message_puncture_request.identifier,self.lan_addr,self.wan_addr)
        self.transport.write(message_puncture.packet,lan_walker_address)
        self.transport.write(message_puncture.packet,wan_walker_address)

    def on_puncture(self,packet):
        pass
    def on_missing_identity(self,packet,addr):
        message = self.create_identity()
        self.transport.write(message.packet,addr)
    def on_identity(self,packet):
        pass

    #a bunch of message decoder below:
    def decode_introduction_request(self,packet):
        offset = 23
        #offset = placeholder.offset
        if len(packet) < offset + 21:
            print("insufficient packet length")
        #MemberAuthentication uses sha1
        member_id = packet[offset:offset + 20]
        offset = offset+20
        #uses directDistribution
        global_time, = self._struct_Q.unpack_from(packet, offset)
        print("global time is:" + str(global_time))
        offset = offset + 8
        self._global_time = global_time


        destination_ip, destination_port = self._struct_4SH.unpack_from(packet, offset)
        destination_address = (inet_ntoa(destination_ip), destination_port)
        print("destination address is:"+ str(destination_address))
        offset += 6

        source_lan_ip, source_lan_port = self._struct_4SH.unpack_from(packet, offset)
        source_lan_address = (inet_ntoa(source_lan_ip), source_lan_port)
        print("source_lan_address is: "+ str(source_lan_address))
        offset += 6

        source_wan_ip, source_wan_port = self._struct_4SH.unpack_from(packet, offset)
        source_wan_address = (inet_ntoa(source_wan_ip), source_wan_port)
        print("source_wan_address is: "+str(source_wan_address))
        offset += 6

        flags, identifier = self._struct_BH.unpack_from(packet, offset)
        offset += 3

        advice = self._decode_advice_map.get(flags & int("1", 2))
        print("advice is: "+str(advice))

        signiture = packet[offset:]
        prefix = packet[0:offset]

        #message = Message.introduction_request()
        #message.destination_addr = destination_address
        #message.sender_lan_addr = source_lan_address
        #message.sender_wan_addr = source_wan_address
        #message.identifier = identifier
        #message.mid = member_id
        #message.global_time = global_time
        #message.signiture = signiture
        #message.prefix = self.prefix
        #message.packet = packet

        message=Message.message(message_type=246,destination_address=destination_address,source_lan_address=source_lan_address,source_wan_address=source_wan_address,identifier=identifier,
                                mid=self.mid,global_time=global_time,signiture=signiture,prefix=prefix,packet=packet)
        return message


    def decode_introduction_response(self,packet):
        #offset = placeholder.offset
        offset = 23
        #introduction request use MemberAuthentication
        member_id = packet[offset:offset + 20]
        offset = offset+20
        global_time, = self._struct_Q.unpack_from(packet, offset)
        self._global_time = global_time
        print("global time is:" + str(global_time))
        offset = offset + 8
        #it is time to decode the payload
        destination_ip, destination_port = self._struct_4SH.unpack_from(packet, offset)
        destination_address = (inet_ntoa(destination_ip), destination_port)
        print("destination address is:"+ str(destination_address))
        offset += 6

        source_lan_ip, source_lan_port = self._struct_4SH.unpack_from(packet, offset)
        source_lan_address = (inet_ntoa(source_lan_ip), source_lan_port)
        print("source_lan_address is: "+ str(source_lan_address))
        offset += 6

        source_wan_ip, source_wan_port = self._struct_4SH.unpack_from(packet, offset)
        source_wan_address = (inet_ntoa(source_wan_ip), source_wan_port)
        print("source_wan_address is: "+str(source_wan_address))
        offset += 6

        introduce_lan_ip, introduce_lan_port = self._struct_4SH.unpack_from(packet, offset)
        lan_introduction_address = (inet_ntoa(introduce_lan_ip), introduce_lan_port)
        print("lan_introduction_address is: "+str(lan_introduction_address))
        offset += 6

        introduce_wan_ip, introduce_wan_port = self._struct_4SH.unpack_from(packet, offset)
        wan_introduction_address = (inet_ntoa(introduce_wan_ip), introduce_wan_port)
        print("wan_introduction_address is:" +str(wan_introduction_address))
        offset += 6

        flags, identifier, = self._struct_BH.unpack_from(packet, offset)
        offset += 3

        connection_type = self._decode_connection_type_map.get(flags & int("11000000", 2))
        print("connection type is: "+ str(connection_type))
        if connection_type is None:
            raise DropPacket("Invalid connection type flag")

        tunnel = self._decode_tunnel_map.get(flags & int("100", 2))
        print("tunnel is:" + str(tunnel))
        if lan_introduction_address==("0.0.0.0",0) and wan_introduction_address ==("0.0.0.0",0):
            print("it is an empty introduction response")

        signiture = packet[offset:]
        prefix = packet[0:offset]

        #message = Message.introduction_response()
        #message.destination_addr = destination_address
        #message.sender_lan_addr = source_lan_address
        #message.sender_wan_addr = source_wan_address
        #message.lan_introducted_addr=lan_introduction_address
        #message.wan_introducted_addr = wan_introduction_address
        #message.lan_introduction_address = lan_introduction_address
        #message.wan_introduction_address = wan_introduction_address
        #message.identifier = identifier
        #message.mid = member_id
        #message.global_time = global_time
        #message.signiture = signiture
        #message.prefix = self.prefix
        #message.packet = packet

        message=Message.message(message_type=245,destination_address=destination_address,source_lan_address=source_lan_address,source_wan_address=source_wan_address,lan_introduction_address=lan_introduction_address,
                                wan_introduction_address=wan_introduction_address,identifier=identifier,mid=member_id,global_time=global_time,signiture=signiture,prefix=self.prefix,packet=packet)
        return message

    #this function is never called for now, but we may need it later for statistical information
    def decode_missing_identity(self,packet):
        offset = 23
        #offset = placeholder.offset
        #missing-identity message us NoAuthentication
        key_length = 0
        #it use PublicResoulution, so we need to do nothing
        #it use directDitribution, we need to take out the global time
        global_time = self._struct_Q.unpack_from(packet,offset)
        print("the global time is: "+str(global_time[0]))
        self._global_time = global_time[0]

        #message = Message.missing_identity()
        #message.packet = packet
        message=Message.message(message_type=247,packet=packet)

    def decode_puncture_request(self,packet):
        #offset = placeholder.offset
        offset = 23
        #puncture-request uses NoAuthentication
        #puncture-request uses DirectDistribution
        global_time, = self._struct_Q.unpack_from(packet, offset)
        print("global time is:" + str(global_time))
        offset = offset + 8

        if len(packet) < offset + 14:
            print("the length is insufficient")

        lan_walker_ip, lan_walker_port = self._struct_4SH.unpack_from(packet, offset)
        lan_walker_address = (inet_ntoa(lan_walker_ip), lan_walker_port)
        print("lan_walker_address is: "+ str(lan_walker_address))
        offset += 6

        wan_walker_ip, wan_walker_port = self._struct_4SH.unpack_from(packet, offset)
        wan_walker_address = (inet_ntoa(wan_walker_ip), wan_walker_port)
        print("wan_walker_address is: "+ str(wan_walker_address))
        offset += 6

        identifier, = self._struct_H.unpack_from(packet, offset)
        offset += 2

        signiture = packet[offset:]
        prefix = packet[0:offset]

        #message = Message.puncture_request()

        #message.lan_walker_addr = lan_walker_address
        #message.wan_walker_addr = wan_walker_address
        #message.identifier = identifier
        #message.global_time = global_time
        #message.signiture = signiture
        #message.prefix = self.prefix
        #message.packet = packet

        message=Message.message(message_type=250,lan_walker_address=lan_walker_address,wan_walker_address=wan_walker_address,identifier=identifier,
                                global_time=global_time,signiture=signiture,prefix=self.prefix,packet=packet)
        return message

    def decode_puncture(self,packet):
        pass



    #some untility functions listed below

    #get a proper candidate to introduce
    def get_candidate_to_introduce(self,candidate):
        candidate_to_introduce = self.candidate_group.get_candidate_to_introduce(candidate)
        return candidate_to_introduce
    #get a proper candidate to walk
    def get_candidate_to_walk(self):
        candidate_to_walk = self.candidate_group.get_candidate_to_walk()
        return candidate_to_walk


    def get_lan_IP(self,addr):
        #try to connect to tracker to determine the ip we used
        #because a device may have multiple network interfaces (e.g. a Wifi and wire network while one of them
        #is not connected to public network)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(addr)
        sock_IP = s.getsockname()[0]
        s.close()
        return sock_IP

    #@staticmethod
    #def get_addr_from_string(address):
            #convert a string to (IP,PORT) tuple
        #addr = address.split(":")
        #addr_tuple = (addr[0],addr[1])
        #return addr_tuple

        #get the majority votes
    def get_majority_vote(self):
        max_vote = 0
        majority = self.wan_ip+":"+str(self.wan_port)
        for key in self.WAN_VOTE:
            num_vote = len(self.WAN_VOTE[key])
            if num_vote>max_vote:
                majority = key
        majority_list = majority.split(":")
        majority_IP = majority_list[0]
        majority_PORT = int(majority_list[1])
        return (majority_IP,majority_PORT)

    #take a wan vote, possible to change the wan address basing on the votes
    def wan_address_vote(self,address,candidate_addr):
        assert isinstance(address,tuple),type(address)
        assert isinstance(candidate_addr,tuple),type(candidate_addr)
        #@param:addr my address which is perceived by the voter
        #@param:candidate_addr the candidate's (voter) addr
        change_flag = 0
        IP = address[0]
        PORT = address[1]
        ADDR = IP+":"+str(PORT)
        if ADDR in self.WAN_VOTE:
            candidate_vote_list = self.WAN_VOTE[ADDR]
            if candidate_addr not in candidate_vote_list:
                self.WAN_VOTE[ADDR].append(candidate_addr)
                change_flag = 1
        else:
            self.WAN_VOTE[ADDR] = [candidate_addr]
            change_flag = 1
        #if there is any update in WAN_VOTE
        if (change_flag == 1):
            new_WAN_ADDR = self.get_majority_vote()
            self.wan_ip = new_WAN_ADDR[0]
            self.wan_port=new_WAN_ADDR[1]
            self.wan_addr = new_WAN_ADDR

    def get_netmask(self,address):
        interfaces = Walker._get_interface_addresses()
        for interface in interfaces:
            if(interface.address==address):
                return interface.netmask
        return None
    def run(self):
        self.reactor.run()
    def stop(self):
        self.reactor.stop()

    @staticmethod
    def _get_interface_addresses():
        """
        Yields Interface instances for each available AF_INET interface found.

        An Interface instance has the following properties:
        - name          (i.e. "eth0")
        - address       (i.e. "10.148.3.254")
        - netmask       (i.e. "255.255.255.0")
        - broadcast     (i.e. "10.148.3.255")
        """
        class Interface(object):

            def __init__(self, name, address, netmask, broadcast):
                self.name = name
                self.address = address
                self.netmask = netmask
                self.broadcast = broadcast
                self._l_address, = unpack_from(">L", inet_aton(address))
                self._l_netmask, = unpack_from(">L", inet_aton(netmask))

            def __contains__(self, address):
                assert isinstance(address, str), type(address)
                l_address, = unpack_from(">L", inet_aton(address))
                return (l_address & self._l_netmask) == (self._l_address & self._l_netmask)

            def __str__(self):
                return "<{self.__class__.__name__} \"{self.name}\" addr:{self.address} mask:{self.netmask}>".format(self=self)

            def __repr__(self):
                return "<{self.__class__.__name__} \"{self.name}\" addr:{self.address} mask:{self.netmask}>".format(self=self)

        try:
            for interface in netifaces.interfaces():
                try:
                    addresses = netifaces.ifaddresses(interface)

                except ValueError:
                    # some interfaces are given that are invalid, we encountered one called ppp0
                    pass

                else:
                    for option in addresses.get(netifaces.AF_INET, []):
                        try:
                            yield Interface(interface, option.get("addr"), option.get("netmask"), option.get("broadcast"))

                        except TypeError:
                            # some interfaces have no netmask configured, causing a TypeError when
                            # trying to unpack _l_netmask
                            pass
        except OSError, e:
            #logger = logging.getLogger("dispersy")
            #logger.warning("failed to check network interfaces, error was: %r", e)
            print ("OSError")

if __name__ == "__main__":
    walker = Walker(port=25000)
    #walker.transport.write("hahahahaha222233333",("8.8.8.8",8))
    #walker.listening_port=walker.reactor.listenUDP(walker.lan_port, walker)
    #walker.reactor.run()
    walker.run()