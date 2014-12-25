'''
Created on Dec 21, 2014

@author: Marcel Enguehard
'''

import SocketServer,socket,config
from dhcp_message import DHCP_message,dhcp_magic_cookie
from network_utils import create_UDP_packet, get_nic_addr,\
    get_subnet_mask_from_prefix, get_broadcast_addr

class DHCP_handler(SocketServer.DatagramRequestHandler):
    
    def handle(self):
        if self.is_DHCP_packet(): 
            try:
                request=DHCP_message(payload=self.request[0])
            except BaseException:
                return            
            print str(request)+" from "+str(self.client_address)
            
            answer=None
            if request.dhcp_type==1: #DHCP_discover
                answer=self.handle_dhcp_discover(request)
            elif request.dhcp_type==3: #DHCP_request
                answer=self.handle_dhcp_request(request)
            
            self.send(answer)
            
            print "Sent: "+str(answer)
        else:
            print "Wrong format for packet..."
    
    #ie: BOOTREQUEST - 10mb ethernet - Address length=6 - 0hops and DHCP magic cookie is present    
    def is_DHCP_packet(self):
        data=self.request[0]
        return data[0:4]=="\x01\x01\x06\x00" and data[236:240]==dhcp_magic_cookie
    
    def handle_dhcp_discover(self,request):
        attr_ip = self.server.get_next_ip()
        answer = DHCP_message(orig_request=request,message_type="DHCPOFFER")
        answer.set_client_ip_addr(attr_ip)
        return answer
    
    #TODO: Implement an actual policy, not just "accept every request"
    def handle_dhcp_request(self,request):
        requested_ip = socket.inet_ntoa(request.dhcp_options[50].payload)
        print request.chaddr+" requested "+requested_ip
        if self.server.is_ip_addr_free(requested_ip) or self.server.who_has_ip(requested_ip) == request.chaddr:
            answer = DHCP_message(orig_request=request,message_type="DHCPACK") #DHCPACK
            answer.set_client_ip_addr(requested_ip)
            answer.set_dhcp_option(51, config.LEASE_TIME) #Lease time
            answer.set_dhcp_option(28, get_broadcast_addr(config.IP_POOL)) #Broadcast address
            answer.set_dhcp_option(1,get_subnet_mask_from_prefix(config.IP_POOL)) #subnet mask
            self.server.register_user(requested_ip,answer.chaddr)
        else:
            answer = DHCP_message(orig_request=request,message_type="DHCPNAK") #DHCPNAK
        return answer
    
    #Send a DHCP packet according to the parameters set in answer
    def send(self,answer):
        #If the client requires broadcast or if it as a DHCPNAK       
        if answer.broadcast_flag or answer.dhcp_type==6: 
            dest_ip_address = "255.255.255.255" #Broadcast address for unconfigured hosts.
        else:
            dest_ip_address = answer.yiaddr
            
        #Since the other host does not respond to ARP, to send the packet we need to use AF_PACKET sockets to specify manually its L2 address    
        answer_data = create_UDP_packet(get_nic_addr(config.INTERFACE),answer.chaddr,config.SERVER_IP,dest_ip_address,config.SERVER_PORT,self.client_address[1],''.join(answer.to_payload()))
        answer_socket = socket.socket(socket.AF_PACKET,socket.SOCK_RAW)
        answer_socket.bind((config.INTERFACE,0))
        answer_socket.send(''.join(answer_data))