import random
import time
from Wcandidate import Wcandidate
import netaddr
class WcandidateGroup:
	#WALK_LIMIT=57.5
	#STUMBLE_LIMIT=57.5
	#INTRO_LIMIT = 27.5
	#all_candidates = []
	#trusted_candidates = [] #0.5% probability, this list should never be empty, should contain at least one tracker
	#walk_candidates = [] #49.75% probability
	#stumble_candidates = [] #24.825%probability
	#intro_candidates= [] #24.825%probability
	#introduce_flag = 0;#even numbers indicate walk_candidates, odd numbers indicate stumble_candidates
	#walk_index =0; #the walk_candidates that should be introduced.
	#stumble_index=0 # the stumble_candidates that should be introduced
	def __init__(self):
		self.WALK_LIMIT=57.5
		self.STUMBLE_LIMIT=57.5
		self.INTRO_LIMIT = 27.5
		self.all_candidates = []
		self.trusted_candidates = [] #0.5% probability, this list should never be empty, should contain at least one tracker
		self.walk_candidates = [] #49.75% probability
		self.stumble_candidates = [] #24.825%probability
		self.intro_candidates= [] #24.825%probability
		self.introduce_flag = 0;#even numbers indicate walk_candidates, odd numbers indicate stumble_candidates
		self.walk_index =0; #the walk_candidates that should be introduced.
		self.stumble_index=0 # the stumble_candidates that should be introduced
		print "initializing trusted_list"
		tracker = Wcandidate(("127.0.0.1",1235),("127.0.0.1",1235),"255,255.255.255")
		#tracker2 = Wcandidate((u"130.161.119.206"      , 6421),(u"130.161.119.206"      , 6421),"255,255.255.255")
		#tracker3 = Wcandidate((u"130.161.119.206"      , 6422),(u"130.161.119.206"      , 6422),"255,255.255.255")
		#tracker4 = Wcandidate((u"131.180.27.155"       , 6423),(u"131.180.27.155"       , 6423),"255,255.255.255")
		#tracker5 = Wcandidate((u"83.149.70.6"          , 6424),(u"83.149.70.6"          , 6424),"255,255.255.255")
		#tracker6 = Wcandidate((u"95.211.155.142"       , 6427),(u"95.211.155.142"       , 6427),"255,255.255.255")
		#tracker7 = Wcandidate((u"95.211.155.131"       , 6428),(u"95.211.155.131"       , 6428),"255,255.255.255")
		#tracker8 = Wcandidate((u"dispersy1.tribler.org", 6421),(u"dispersy1.tribler.org", 6421))
		#tracker9 = Wcandidate((u"dispersy2.tribler.org", 6422),(u"dispersy2.tribler.org", 6422))
		#tracker10 = Wcandidate((u"dispersy3.tribler.org", 6423),(u"dispersy3.tribler.org", 6423))
		#tracker11 = Wcandidate((u"dispersy4.tribler.org", 6424),(u"dispersy4.tribler.org", 6424))
		#tracker12 = Wcandidate((u"dispersy7.tribler.org", 6427),(u"dispersy7.tribler.org", 6427))
		#tracker13 = Wcandidate((u"dispersy8.tribler.org", 6428),(u"dispersy8.tribler.org", 6428))
		
		self.trusted_candidates.append(tracker)
		#self.trusted_candidates.append(tracker2)
		#self.trusted_candidates.append(tracker3)
		#self.trusted_candidates.append(tracker4)
		#self.trusted_candidates.append(tracker5)
		#self.trusted_candidates.append(tracker6)
		#self.trusted_candidates.append(tracker7)
		#self.trusted_candidates.append(tracker8)
		#self.trusted_candidates.append(tracker9)
		#self.trusted_candidates.append(tracker10)
		#self.trusted_candidates.append(tracker11)
		#self.trusted_candidates.append(tracker12)
		#self.trusted_candidates.append(tracker13)
		print "the length of trusted list is:"
		print len(self.trusted_candidates)

	#check are all lists empty
	#def has_candidate(self):
		#if(len(self.trusted_candiates)==0 and len(self.walk_candidates)==0 and len(self.stumble_candidates)==0 and len(self.intro_candidates) ==0):
			#return False
		#else:
			#return True
	def choose_group(self):
		#return one of the group basing on probability
		#it is possible to return a empty list
		#@return(type,list)
		if(len(self.walk_candidates)==0 and len(self.stumble_candidates)==0 and len(self.intro_candidates)==0):
			return ("trusted",self.trusted_candidates)
		num_random = random.random()*1000
		if(num_random>995):
			return ("trusted",self.trusted_candidates)
		elif(num_random>497.5):
			return ("walk",self.walk_candidates)
		elif(num_random>248.25):
			return ("stumble",self.stumble_candidates)
		else:
			return ("intro",self.intro_candidates)

	def get_candidate_walk_time(self,candidate):
		return candidate.last_walk_time
	def get_candidate_stumble_time(self,candidate):
		return candidate.last_stumble_time
	def get_candidate_intro_time(self,candidate):
		return candidate.last_intro_time

	def add_candidate_to_walk_list(self,candidate):
		self.clean_stale_candidates()
		if not (self.is_in_list(candidate,self.trusted_candidates) or self.is_in_list(candidate,self.walk_candidates)):
			self.walk_candidates.append(candidate)
		print "the walk_list is now:"
		for candidate in self.walk_candidates:
			print candidate.get_WAN_ADDR()


	def add_candidate_to_stumble_list(self,candidate):
		self.clean_stale_candidates()
		if not (self.is_in_list(candidate,self.trusted_candidates) or self.is_in_list(candidate,self.walk_candidates) or self.is_in_list(candidate,self.stumble_candidates)):
			self.stumble_candidates.append(candidate)
		print "the stumble_list is now:"
		for candidate in self.stumble_candidates:
			print [candidate.get_LAN_ADDR(),candidate.get_WAN_ADDR()]


	def add_candidate_to_intro_list(self,candidate):
		self.clean_stale_candidates()
		if not (self.is_in_list(candidate,self.trusted_candidates) or self.is_in_list(candidate,self.walk_candidates) or self.is_in_list(candidate,self.stumble_candidates) or self.is_in_list(candidate,self.intro_candidates)):
			self.intro_candidates.append(candidate)
		print "the intro_list is now:"
		for candidate in self.intro_candidates:
			print candidate.get_WAN_ADDR()


	#check if the candidate is already in a list
	def is_in_list(self,candidate,candidate_list):
		for c in candidate_list:
			if self.is_same_candidate(candidate,c):
				return True
			else:
				continue
		return False

	def get_candidate_to_walk(self):
		#get the oldest candiate in the chosen group
		self.clean_stale_candidates()
		candidates_list =[]
		list_type=""
		#loop until we get a non-empty list
		while(len(candidates_list)==0):
			list_type,candidates_list = self.choose_group()
		if(list_type=="trusted"):
			random_index = random.randint(0,len(self.trusted_candidates)-1)
			print candidates_list[random_index].get_WAN_ADDR()
			return candidates_list[random_index]
		elif(list_type=="walk"):
			candidates_list_sorted = sorted(candidates_list,key=self.get_candidate_walk_time)
			candidates_list_sorted.reverse()
			return candidates_list_sorted[0]
		elif(list_type=="stumble"):
			candidates_list_sorted = sorted(candidates_list,key=self.get_candidate_stumble_time)
			candidates_list_sorted.reverse()
			return candidates_list_sorted[0]
		elif(list_type=="intro"):
			candidates_list_sorted = sorted(candidates_list,key=self.get_candidate_intro_time)
			candidates_list_sorted.reverse()
			return candidates_list_sorted[0]
		else:
			#print "this is before that None"
			return None

	def is_same_candidate(self,candidate1,candidate2):
		if(candidate1.get_LAN_ADDR()==candidate2.get_LAN_ADDR() and candidate1.get_WAN_ADDR()==candidate2.get_WAN_ADDR()):
			#print "they are same candidates"
			#print [(candidate1.get_LAN_ADDR(),candidate1.get_WAN_ADDR()),(candidate2.get_LAN_ADDR(),candidate2.get_WAN_ADDR())]
			return True
		else:
			#print "they are different candidates"
			#print [(candidate1.get_LAN_ADDR(),candidate1.get_WAN_ADDR()),(candidate2.get_LAN_ADDR(),candidate2.get_WAN_ADDR())]
			return False
	#check if the two address are in same NAT
	#has some bugs, of no use for now.
	def is_in_same_NAT(self,lan1,netmask1,lan2,netmask2):
		cidr1 = str(netaddr.IPAddress(netmask1).netmask_bits())
		network1 = netaddr.IPNetwork(lan1+"/"+cidr1)
		cidr2 = str(netaddr.IPAddress(netmask2).netmask_bits())
		network2 = netaddr.IPNetwork(lan2+"/"+cidr2)
		network1_networkid = str(network1.network)
		network2_networkid = str(network2.network)
		if(network1_networkid==network2_networkid):
			return True
		else:
			return False

	#return None if there is no proper candidate
	def get_candidate_to_introduce(self,candidate):
		self.clean_stale_candidates()
		if(self.introduce_flag%2==0 and len(self.walk_candidates)!=0):
			if(len(self.walk_candidates)<=self.walk_index):
				self.walk_index=max(0,len(self.walk_candidates)-1)
			print "checking walk list"
			self.introduce_flag = self.introduce_flag+1
			i=0
			while (i<len(self.walk_candidates)):
				candidate_to_introduce = self.walk_candidates[self.walk_index]
				#should not return the request candidate itself to the request candiate
				i=i+1
				if not self.is_same_candidate(candidate_to_introduce,candidate):
					self.walk_index = (self.walk_index+1)%len(self.walk_candidates)
					return candidate_to_introduce
				else:
					self.walk_index = (self.walk_index+1)%len(self.walk_candidates)
					continue
			self.walk_index = (self.walk_index+1)%len(self.walk_candidates)
			return None
		self.introduce_flag = self.introduce_flag+1
		if(self.introduce_flag%2==1 and len(self.stumble_candidates)!=0):
			if(len(self.stumble_candidates)<=self.stumble_index):
				self.stumble_index=max(0,len(self.stumble_candidates)-1)
			print "checking stumble list"
			self.introduce_flag = self.introduce_flag+1
			i=0
			while (i<len(self.stumble_candidates)):
				candidate_to_introduce = self.stumble_candidates[self.stumble_index]
				i=i+1
				if not self.is_same_candidate(candidate_to_introduce,candidate):
					self.stumble_index = (self.stumble_index+1)%len(self.stumble_candidates)
					return candidate_to_introduce
				else:
					self.stumble_index = (self.stumble_index+1)%len(self.stumble_candidates)
					continue
			self.stumble_index = (self.stumble_index+1)%len(self.stumble_candidates)
			return None
	def clean_stale_candidates(self):
		now = time.time()
		walk_candidates_to_remove=[]
		for candidate in self.walk_candidates:
			if(now-(candidate.last_walk_time)>self.WALK_LIMIT):
				print "cleaning a time out walk candidate........"+str(candidate.LAN_ADDR)
				#self.walk_candidates.remove(candidate)
				walk_candidates_to_remove.append(candidate)
				#self.all_candidates.remove(candidate)
				if(len(self.walk_candidates)!=0):
					self.walk_index = self.walk_index%len(self.walk_candidates)
				else:
					self.walk_index = 0;
		self.walk_candidates =[x for x in self.walk_candidates if x not in walk_candidates_to_remove]
		stumble_candidates_to_remove =[]
		for candidate in self.stumble_candidates:
			if(now-(candidate.last_stumble_time)>self.STUMBLE_LIMIT):
				print "cleaning a time out stumble candidate........"+str(candidate.LAN_ADDR)
				#self.stumble_candidates.remove(candidate)
				stumble_candidates_to_remove.append(candidate)
				#self.all_candidates.remove(candidate)
				if(len(self.stumble_candidates)!=0):
					self.stumble_index = self.stumble_index%len(self.stumble_candidates)
					#print "stumble index is now: "+str(self.stumble_index)
				else:
					#print "stumble index is now: "+str(self.stumble_index)
					self.stumble_index = 0
				continue
		self.stumble_candidates = [x for x in self.stumble_candidates if x not in stumble_candidates_to_remove]
		intro_candidates_to_remove =[]
		for candidate in self.intro_candidates:
			if(now-(candidate.last_intro_time)>self.INTRO_LIMIT):
				#self.intro_candidates.remove(candidate)
				intro_candidates_to_remove.append(candidate)
				#self.all_candidates.remove(candidate)
		self.intro_candidates = [x for x in self.intro_candidates if x not in intro_candidates_to_remove]

