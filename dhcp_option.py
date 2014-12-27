'''
Created on Dec 22, 2014

@author: Marcel Enguehard
'''
import config,struct,logging
from _socket import inet_aton

logger = logging.getLogger("DHCP_server")

class DHCP_option:
    #See RFC2132 for options explanations: https://tools.ietf.org/html/rfc2132
    #For each option number, stores the corresponding value in config.py
    dhcp_options={
                  1:  "Subnet Mask",
                  2:  "Time offset",
                  3:  "router",
                  6:  "Domain name server option",
                  12: "Host name option",
                  15: "Domain Name",
                  26: "Interface MTU",
                  28: "Broadcast address",
                  42: "NTP Servers",
                  44: "Netbios over TCP/IP Name Server",
                  47: "Netbios over TCP/IP scope",
                  50: "Requested IP Address",
                  51: "IP Address Lease Time",
                  52: "Option Overload",
                  53: "Message Type",
                  54: "Server Identifier",
                  55: "Parameter Request List",
                  56: "Message",
                  57: "Maximum DHCP Message Size",
                  58: "Renewal Time Value",
                  59: "Rebinding Time Value",
                  60: "Vendor class identifier",
                  61: "Client-identifier",
                  119:"Domain Search",
                  121:"Classless Static Route"
    }
    
    dhcp_attributes={
                     1:   "SUBNET_MASK",
                     3:   "ROUTERS",
                     6:   "DNS_SERVERS",
                     28:  "BROADCAST_ADDR",
                     42:  "NTP_SERVERS",
                     51:  "LEASE_TIME",
                     }
    
    def __init__(self,option_number,option_length,option_payload):
        self.number = option_number
        self.name = DHCP_option.dhcp_options[self.number]
        self.length = option_length
        self.payload = option_payload
        
    def __str__(self):
        return "Option "+str(self.number)+": "+DHCP_option.dhcp_options[self.number]+", size: "+self.length+", payload:"+self.payload
        
#Create an option field from a request. To be gradually completed
def handle_option_request(request,option_number):
    if option_number in [1,28]:
        option = create_ip_option(option_number)
    elif option_number == 51:
        option = create_integer_option(option_number)
    elif option_number in [6,3,42]:
        option = create_mult_ips_option(option_number)
    else:
        logger.warning('Option number "%s" is not supported',DHCP_option.dhcp_options[option_number])
        return
    
    if option is None:
        logger.warning('Could not set option "%s" for absence of configuration',DHCP_option.dhcp_options[option_number])
    else:
        request.dhcp_options[option_number] = option

#Creates an option containing a 32bit integer
def create_integer_option(option_number):
    option_name = DHCP_option.dhcp_attributes[option_number]
    if hasattr(config,option_name):
        return DHCP_option(option_number,4,struct.pack("!I",getattr(config, option_name)))
    else: 
        return None

#Creates an option containing only ONE IP address    
def create_ip_option(option_number):
    option_name = DHCP_option.dhcp_attributes[option_number]
    if hasattr(config, option_name):
        return DHCP_option(option_number,4,inet_aton(getattr(config, option_name)))
    else:
        return None

#Creates an option containing SEVERAL IP address    
def create_mult_ips_option(option_number):
    option_name = DHCP_option.dhcp_attributes[option_number]
    if hasattr(config,option_name):
        ip_array = getattr(config,option_name)
        return DHCP_option(option_number,4*len(ip_array),''.join(map(inet_aton,ip_array)))
    else:
        return None