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
LEASE_TIME=200
#DNS_SERVERS = ["8.8.8.8"]
#NTP_SERVERS = [SERVER_IP]
##List of IP addresses for router on the local subnet, by order of preference.
ROUTERS = ["10.0.0.1"]

#Keep to False unless you know what you're doing
#See http://tools.ietf.org/html/rfc2563
AUTO_CONFIG = False

#Default mode: logs to console.
#LOG_TO_FILE=True
#LOG_FILE='/var/log/pydhcp.log'
LOG_LEVEL='DEBUG' #Has to be one of 'DEBUG','INFO','WARNING' or 'ERROR'

'''
    CONFIGURATION SCRIPTS
    Do not change anything here.
'''
import network_utils
SUBNET_MASK = network_utils.get_subnet_mask_from_prefix(IP_POOL)
if BROADCAST_ADDR == "default":
    BROADCAST_ADDR = network_utils.get_broadcast_addr(IP_POOL)

if not 'LOG_TO_FILE' in locals():
    LOG_TO_FILE = False
    LOG_FILE = None
    
if not 'LOG_LEVEL' in locals():
    LOG_LEVEL = 'INFO'
    
def get_log_level():
    if LOG_LEVEL == 'DEBUG':
        return 10
    elif LOG_LEVEL == 'INFO':
        return 20
    elif LOG_LEVEL== 'WARNING':
        return 30
    elif LOG_LEVEL == 'ERROR':
        return 40
