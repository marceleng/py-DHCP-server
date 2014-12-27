'''
Created on Dec 21, 2014

@author: Marcel Enguehard
'''

import SocketServer,socket,config,logging
from dhcp_message import DHCP_message,dhcp_magic_cookie
from network_utils import create_UDP_packet, get_nic_addr

class DHCP_handler(SocketServer.DatagramRequestHandler):
    
    def __init__(self,request,client_address,server):
        self.logger = logging.getLogger('DHCP_server')
        SocketServer.DatagramRequestHandler.__init__(self,request,client_address,server)
    
    def handle(self):
        if self.is_DHCP_packet(): 
            try:
                request=DHCP_message(payload=self.request[0])
            except BaseException:
                return            
            self.logger.debug("%s from %s",str(request),str(self.client_address))
            
            answer=None
            if request.dhcp_type==1: #DHCP discover
                answer=self.handle_dhcp_discover(request)
            elif request.dhcp_type==3: #DHCP request
                answer=self.handle_dhcp_request(request)
            elif request.dhcp_type == 4: #DHCPDECLINE
                self.handle_dhcp_decline(request)
                return
            elif request.dhcp_type==7:#DHCP Release
                self.handle_dhcp_release(request)
                return
            elif request.dhcp_type == 8:#DHCP Inform
                answer = self.handle_dhcp_inform(request)
            
            self.send(answer)
            
            self.logger.debug("Sent: %s",str(answer))
        else:
            self.logger.error("Wrong format for packet from %s",self.client_address)
    
    #ie: BOOTREQUEST - 10mb ethernet - Address length=6 - 0hops and DHCP magic cookie is present    
    def is_DHCP_packet(self):
        data=self.request[0]
        return data[0:4]=="\x01\x01\x06\x00" and data[236:240]==dhcp_magic_cookie
    
    '''
        Crafts a DHCPOFFER to respond to a DHCPDISCOVER
    '''
    def handle_dhcp_discover(self,request):
        #If the client requested a free IP address we give it to him
        if request.dhcp_options.has_key(50):
            attr_ip = socket.inet_ntoa(request.dhcp_options[50].payload)
        if not self.server.is_ip_addr_free(attr_ip):
            attr_ip = self.server.get_next_ip()
        answer = DHCP_message(orig_request=request,message_type="DHCPOFFER")
        answer.set_client_ip_addr(attr_ip)
        return answer
    
    '''
        Crafts an answer to a DHCP request (either ACK or NACK)
    '''
    def handle_dhcp_request(self,request):
        if request.dhcp_options.has_key(50):
            requested_ip = socket.inet_ntoa(request.dhcp_options[50].payload)
        else:
            requested_ip = request.ciaddr
        self.logger.debug("%s requested %s",request.chaddr,requested_ip)
        if self.server.is_ip_addr_free(requested_ip) or self.server.who_has_ip(requested_ip) == request.chaddr:
            answer = DHCP_message(orig_request=request,message_type="DHCPACK") #DHCPACK
            answer.set_client_ip_addr(requested_ip)
            self.server.register_user(requested_ip,answer.chaddr)
            self.logger.info("Attributed %s to %s",requested_ip,answer.chaddr)
        else:
            answer = DHCP_message(orig_request=request,message_type="DHCPNAK") #DHCPNAK
        return answer
    
    def handle_dhcp_inform(self,request):
        return DHCP_message(orig_request=request,message_type="DHCPACK")
        
    def handle_dhcp_decline(self,request):
        ip = socket.inet_ntoa(request.dhcp_options[50].payload)
        self.server.register_user(ip,"unknown")
        self.logging.error("client declined offer from server. Check configuration")
    
    '''
        Handles the release of a lease by a client
    '''
    def handle_dhcp_release(self,request):
        released_ip_addr = request.ciaddr
        releasing_mac_addr = request.chaddr
        
        if not self.server.is_ip_addr_free(released_ip_addr) and self.server.who_has_ip(released_ip_addr) == releasing_mac_addr:
            self.server.release_ip(released_ip_addr)
            self.logger.info("%s released %s",releasing_mac_addr,released_ip_addr)
        else:
            self.logger.warning("client releasing wrong IP address")
    
    #Send a DHCP packet according to the parameters set in answer
    def send(self,answer):
        #If the client requires broadcast or if it as a DHCPNAK       
        if answer.broadcast_flag or answer.dhcp_type==6: 
            dest_ip_address = "255.255.255.255" #Broadcast address for unconfigured hosts.
        else:
            dest_ip_address = answer.yiaddr
            
        #Since the other host does not respond to ARP, to send the packet we need to use AF_PACKET sockets to specify manually its L2 address    
        answer_data = create_UDP_packet(get_nic_addr(config.INTERFACE),answer.chaddr,config.SERVER_IP,dest_ip_address,
                                        config.SERVER_PORT,self.client_address[1],''.join(answer.to_payload()),udp_checksum=True)
        answer_socket = socket.socket(socket.AF_PACKET,socket.SOCK_RAW)
        answer_socket.bind((config.INTERFACE,0))
        answer_socket.send(''.join(answer_data))