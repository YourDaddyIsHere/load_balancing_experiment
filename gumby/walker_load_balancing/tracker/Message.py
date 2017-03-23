class introduction_request:
    def __init__(self):
        self.destination_addr=None
        self.sender_lan_addr = None
        self.sender_wan_addr = None
        self.identifier = None
        self.mid=None
        self.global_time = None
        self.signiture = None
        self.message_type =-246
        self.prefix=None
        self.encode_advice_map=None
        self.encode_connection_type_map=None
        self.encode_sync_map=None
        self.packet=None

class introduction_response:
    def __init__(self):
        self.destination_addr=None
        self.sender_lan_addr = None
        self.sender_wan_addr = None
        self.lan_introduced_addr=None
        self.wan_introduced_addr=None
        self.identifier = None
        self.mid=None
        self.global_time = None
        self.signiture = None
        self.message_type =245
        self.prefix=None
        self.encode_advice_map=None
        self.encode_connection_type_map=None
        self.encode_sync_map=None
        self.packet=None


class puncture_request:
    def __init__(self):
        self.lan_walk_addr = None
        self.wan_walker_addr = None
        self.mid=None
        self.global_time = None
        self.signiture = None
        self.message_type =250
        self.prefix=None
        self.packet=None

class puncture:
    def __init__(self):
        self.sender_lan_addr = None
        self.sender_wan_addr = None
        self.message_type = 249

class identity:
    def __init__(self):
        self.public_key=None
        self.key_len = None
        self.global_time=None
        self.message_type=248
        self.signiture = None
        self.packet = None

class missing_identity:
    def __init__(self):
        self.global_time=None
        self.packet=None
        self.message_type=247

class message:
    def __init__(self,destination_address=None,source_lan_address=None,source_wan_address=None,lan_introduction_address=None,wan_introduction_address=None,lan_walker_address=None,
                wan_walker_address=None,identifier=None,public_key=None,key_len=None,mid=None,global_time=None,signiture=None,message_type=None,prefix=None,packet=None):
        self.destination_address=destination_address
        self.source_lan_address = source_lan_address
        self.source_wan_address = source_wan_address
        self.lan_introduction_address=lan_introduction_address
        self.wan_introduction_address=wan_introduction_address
        self.lan_walker_address=lan_walker_address
        self.wan_walker_address=wan_walker_address
        self.identifier = identifier
        self.public_key=public_key
        self.key_len = key_len
        self.mid=mid
        self.global_time = global_time
        self.signiture = signiture
        self.message_type =-message_type
        self.prefix=prefix
        self.packet=packet

