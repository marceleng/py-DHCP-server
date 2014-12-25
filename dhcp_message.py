'''
Created on Dec 21, 2014

@author: Marcel Enguehard
'''
from socket import inet_aton,inet_ntoa
from network_utils import mac_hextostr,mac_strtohex
from dhcp_option import DHCP_option, handle_option_request
import config,struct

dhcp_ntot = {1:"DHCPDISCOVER",
              2:"DHCPOFFER",
              3:"DHCPREQUEST",
              4:"DHCPDECLINE",
              5:"DHCPACK",
              6:"DHCPNAK",
              7:"DHCPRELEASE",
              8:"DHCPINFORM"}

dhcp_tton = {
              "DHCPDISCOVER":1,
              "DHCPOFFER":2,
              "DHCPREQUEST":3,
              "DHCPDECLINE":4,
              "DHCPACK":5,
              "DHCPNAK":6,
              "DHCPRELEASE":7,
              "DHCPINFORM":8}

dhcp_magic_cookie = "\x63\x82\x53\x63"

class DHCP_message:
    
    '''
    2 ways of creating an instance:
        1 - From the data of a packet: DHCP_message(data=my_UDP_data)
        2 - From a previous request by specifying the new request type: DHCP_message(request_type=new_type,orig_request=req)
    In (2), new_type has to be a server message, so one of [2,5,6] ("DHCPOFFER","DHCPACK","DHCPNACK")
    '''
    def __init__(self,payload=None,message_type=None,orig_request=None):
        if payload:
            self.create_message_from_payload(payload)
        elif message_type in ["DHCPOFFER","DHCPACK","DHCPNAK"] and orig_request:
            self.create_answer_to_request(orig_request,message_type)
        else:
            pass
    
    def create_answer_to_request(self,orig_request,message_type,new_ip=None):
        self.xid = orig_request.xid
        self.secs = "\x00\x00"
        self.broadcast_flag = orig_request.broadcast_flag
        self.ciaddr = None #TODO: use it if node is in BOUND, RENEW or REBINDING state
        self.yiaddr = "0.0.0.0" #TODO: figure out implementation
        self.siaddr = config.SERVER_IP
        self.giaddr = None
        self.chaddr = orig_request.chaddr
        self.sname = None
        self.file = None
        
        self.dhcp_options = {}
        self.dhcp_options[53] = DHCP_option(53,1,chr(dhcp_tton[message_type]))
        self.dhcp_options[54] = DHCP_option(54,4,config.SERVER_IP)
        self.dhcp_type = dhcp_tton[message_type]
    
    def set_client_ip_addr(self,ip_addr):
        self.yiaddr = ip_addr
    
    #FIXME: does this belong here or in dhcp_option.py?    
    def set_dhcp_option(self,option_number,option_value):
        if option_number is 51: #IP Lease time
            self.dhcp_options[51] = DHCP_option(51,4,struct.pack("!I",option_value))
        elif option_number is 1: #subnet mask
            self.dhcp_options[1] = DHCP_option(1,4,inet_aton(option_value))
        elif option_number is 28: #broadcast address
            self.dhcp_options[28] = DHCP_option(28,4,inet_aton(option_value))
        else:
            raise NotImplementedError("Option number "+option_number+" is not supported")
        
    def create_message_from_payload(self,payload):
        #BOOTP parameters
        self.xid = payload[4:8]
        self.secs = payload[8:10]
        flags = payload[10:12]
        if flags == "\x80\x00":
            self.broadcast_flag=True
        else:
            self.broadcast_flag=False
        self.ciaddr = inet_ntoa(payload[12:16])
        self.yiaddr = inet_ntoa(payload[16:20])
        self.siaddr = inet_ntoa(payload[20:24])
        self.giaddr = inet_ntoa(payload[24:28])
        self.chaddr = mac_hextostr(payload[28:34])
        self.sname = self.get_null_terminated_string(payload[44:108])
        self.file = self.get_null_terminated_string(payload[108:236])
        
        self.parse_DHCP_options(payload[240:])
    
    def parse_DHCP_options(self,payload):
        current_position=0
        self.dhcp_options={}
        while current_position<len(payload):
            option_number = int(payload[current_position].encode('hex'),16)
            if option_number is 255: #255: end
                return
            option_length = int(payload[current_position+1].encode('hex'),16)
            option_payload = payload[current_position+2:current_position+2+option_length]
            current_position = current_position+2+option_length
            if option_number is 53:
                self.handle_message_type(option_payload)
            self.dhcp_options[option_number]=DHCP_option(option_number,option_length,option_payload)
        raise ValueError("No end option in  packet") #Reason: no 'end' option. TODO: do smthg more clever

    def handle_message_type(self,option_payload):
        self.dhcp_type = int(option_payload.encode('hex'),16)
        
    #Convert instance to hexadecimal data ready to be sent
    def to_payload(self):
        payload_size = max(300,(240+self.get_options_size()+1)) #+1 is for option 255: end; 300 is the minimum BOOTP packet size according to RFC1542
        print "Payload size is: "+str(payload_size)
        payload = ["\x00"] * payload_size
        
        #Setting the message op code
        if(self.dhcp_type in [1,3,4,7]):
            payload[0]="\x01" #BOOTREQUEST
        elif self.dhcp_type in [2,5,6]:
            payload[0]="\x02" #BOOTREPLY
            
        #Hardware: ethernet 10mb
        payload[1:4]="\x01\x06\x00"

        payload[4:8] = self.xid
        payload[8:10] = self.secs
        if self.broadcast_flag:
            payload[10:12] = "\x80\x00"
        if self.ciaddr is not None:
            payload[12:16] = inet_aton(self.ciaddr)
        payload[16:20] = inet_aton(self.yiaddr)
        if self.siaddr is not None:
            payload[20:24] = inet_aton(self.siaddr)
        if self.giaddr is not None:
            payload[24:28] = inet_aton(self.giaddr)
        payload[28:34] = mac_strtohex(self.chaddr)
        if self.sname is not None:
            payload[44:108] = self.fill_after_str(self.sname,64)
        if self.file is not None:
            payload[108:236] = self.fill_after_str(self.file,128)
            
        payload[236:240] = dhcp_magic_cookie
        current_pos=240
        for option in self.dhcp_options.itervalues():
            payload[current_pos:current_pos+2+option.length] = chr(option.number) + chr(option.length) + option.payload
            current_pos += (2+option.length)
        payload[current_pos] = "\xff"
        return payload
    
    #Extract the longest possible string terminated by from the data    
    def get_null_terminated_string(self,data):
        return data[0:data.find("\x00")]
    
    #Returns a string whose size is set by field_size containing string and a padding of \0
    def fill_after_str(self,string,field_size):
        if(field_size < len(string)):
            raise RuntimeError("string too big for field size: "+string) #TODO: do something more clever
        output=[None]*field_size
        output[0:len(string)] = string
        output[len(string):field_size] = ["\x00"]*(field_size-len(string))
        return output
    
    #Returns the total size of the option fields in the payload in octets
    def get_options_size(self):
        total=0
        for option in self.dhcp_options.itervalues():
            try:
                total += (2+option.length)
            except AttributeError:
                print "Error in message "+str(self)+" for option "+str(option)
        return total
    
    def __str__ (self):
        return dhcp_ntot[self.dhcp_type]+" "+self.xid.encode('hex')+" from "+self.chaddr