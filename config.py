'''
Created on Dec 20, 2014

@author: Marcel Enguehard
'''

'''
    SERVER CONFIGURATION
'''
SERVER_IP="10.0.0.1"
SERVER_PORT=67
INTERFACE="eth0"

'''
    SUBNET CONFIGURATION
'''
IP_POOL="10.0.0.0/8" #We might want to change that to make it more flexible (you don't necessarily want to be able to attribute every address in the subnet 
BROADCAST_ADDR="default"


#Lease time of a DHCP address in seconds
LEASE_TIME=90
#DNS_SERVERS = ["8.8.8.8"]
#NTP_SERVERS = [SERVER_IP]
##List of IP addresses for router on the local subnet, by order of preference.
ROUTERS = ["10.0.0.1"]

'''
    CONFIGURATION SCRIPTS
    Do not change anything here.
'''
import network_utils
SUBNET_MASK = network_utils.get_subnet_mask_from_prefix(IP_POOL)
if BROADCAST_ADDR == "default":
    BROADCAST_ADDR = network_utils.get_broadcast_addr(IP_POOL)