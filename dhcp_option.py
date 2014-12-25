'''
Created on Dec 22, 2014

@author: Marcel Enguehard
'''

class DHCP_option:
    #See RFC2132 for options explanations: https://tools.ietf.org/html/rfc2132
    dhcp_options={
                  1: "Subnet Mask",
                  12:"Host name option",
                  28: "Broadcast address",
                  50:"Requested IP Address",
                  51:"IP Address Lease Time",
                  52:"Option Overload",
                  53:"Message Type",
                  54:"Server Identifier",
                  55:"Parameter Request List",
                  56:"Message",
                  57:"Maximum DHCP Message Size",
                  58:"Renewal Time Value",
                  59:"Rebinding Time Value",
                  60:"Vendor class identifier",
                  61:"Client-identifier"}
    
    def __init__(self,option_number,option_length,option_payload):
        self.number = option_number
        self.name = DHCP_option.dhcp_options[self.number]
        self.length = option_length
        self.payload = option_payload
        
    def __str__(self):
        return "Option "+str(self.number)+": "+DHCP_option.dhcp_options[self.number]+", size: "+self.length+", payload:"+self.payload
        
#Create an option field from a request. To be gradually completed
def handle_option_request(request,option_number):
    pass