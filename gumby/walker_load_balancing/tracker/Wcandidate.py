import time
import socket
class Wcandidate:
	#wan and lan address should be a tuple (ip,port)
	WALK_LIMIT=57.5
	STUMBLE_LIMIT=57.5
	INTRO_LIMIT = 27.5
	NETMASK = ""
	WAN_ADDR = None
	last_walk_time = 0 
	last_stumble_time = 0
	last_intro_time = 0
	def __init__(self,lan,wan,netmask="255.255.255.0"):
		assert isinstance(lan,tuple)
		assert isinstance(wan,tuple)
		self.LAN_ADDR = lan
		self.WAN_ADDR = wan
		self.last_walk_time = time.time()
		self.last_stumble_time = time.time()
		self.last_intro_time = time.time()
		self.NETMASK = netmask


	def get_LAN_IP(self):
		LAN_IP = socket.gethostbyname(self.LAN_ADDR[0])
		return self.LAN_IP[0]
	def get_LAN_PORT(self):
		return (self.get_LAN_IP(),self.get_LAN_PORT())
	def get_LAN_ADDR(self):
		return self.LAN_ADDR
	def get_NETMASK(self):
		return self.NETMASK
	def get_WAN_IP(self):
		WAN_IP = socket.gethostbyname(self.WAN_ADDR[0])
		return WAN_IP
	def get_WAN_PORT(self):
		return self.WAN_ADDR[1]
	def get_WAN_ADDR(self):
		return (self.get_WAN_IP(),self.get_WAN_PORT())
