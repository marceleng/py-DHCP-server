'''
Created on Dec 21, 2014

@author: Marcel Enguehard
'''

import SocketServer,socket,threading, time
import config
import network_utils
from dhcp_handler import DHCP_handler

class DHCP_server(SocketServer.ThreadingMixIn,SocketServer.UDPServer):
    def __init__(self,ip,port,ip_pool,RequestHandlerClass):
        SocketServer.UDPServer.__init__(self, ("",port), RequestHandlerClass)
        print "Server starting..."
        self.ip=ip
        self.port=port
        self.ip_pool = network_utils.get_ip_pool_from_string(ip_pool)
        print "IP addresses pool: "+str(self.ip_pool)
        self.current_ip = self.ip_pool[0]
        print "Current ip: "+self.current_ip
        self.attributed_ips = {self.ip : "server","10.0.0.0":"reserved"}
        self.lease_handler = Lease_manager(self)
    
    #Returns the next available IP in the pool        
    def get_next_ip(self):
        while self.attributed_ips.has_key(self.current_ip):
            self.current_ip = network_utils.get_next_ip(self.ip_pool,self.current_ip)
        return self.current_ip
    
    def is_ip_addr_free(self,ip):
        return self.is_ip_attributable(ip) and not self.attributed_ips.has_key(ip)
    
    def is_ip_attributable(self,ip):
        return network_utils.ip4_aton(ip)>network_utils.ip4_aton(self.ip_pool[0]) and network_utils.ip4_aton(ip)<network_utils.ip4_aton(self.ip_pool[1])
    
    def who_has_ip(self,ip):
        return self.attributed_ips[ip]
    
    def release_ip(self,ip):
        self.attributed_ips.pop(ip)
        self.lease_handler.remove_ip(ip)
    
    #Adds a ip/mac pair to the dictionary /!\ use get_next_ip first to be sure not to override anything
    def register_user(self,ip,mac):
        self.attributed_ips[ip]=mac
        self.lease_handler.add_ip(ip, config.LEASE_TIME)
    
    def serve_forever(self, poll_interval=0.5):
        self.lease_handler.start()
        SocketServer.UDPServer.serve_forever(self, poll_interval=poll_interval)
    
    def shutdown(self):
        self.lease_handler.stop()
        self.lease_handler.join()
        SocketServer.UDPServer.shutdown(self)
        
class Lease_manager(threading.Thread):
    def __init__(self,server):
        threading.Thread.__init__(self)
        self.leased_ips = {}
        self._is_started = threading.Event()
        self.server = server
    
    '''
        IP database management methods
    '''    
    def add_ip(self,ip,lease_duration):
        self.leased_ips[ip] = lease_duration + time.time()
        
    def remove_ip(self,ip):
        self.leased_ips.pop(ip)
        
    def get_ip_expiring_time(self,ip):
        return self.leased_ips[ip]
    
    '''
        Runtime management methods
    '''
    def run(self):
        self._is_started.set()
        while self.started():
            for ip in self.leased_ips.iterkeys():
                if self.leased_ips[ip] < time.time():
                    self.server.release_ip(ip)
                    self.remove_ip(ip)
            time.sleep(60) #FIXME: Magic constant, does it need to be set differently?
            
    def stop(self):
        self._is_started.clear()
        
    def started(self):
        self._is_started.is_set()
        
        
server=DHCP_server(config.SERVER_IP,config.SERVER_PORT,config.IP_POOL,DHCP_handler)
server.socket.setsockopt(socket.SOL_SOCKET, 25, config.INTERFACE+"\0")
try:
    server.serve_forever()
except (KeyboardInterrupt,SystemExit):
    server.shutdown()