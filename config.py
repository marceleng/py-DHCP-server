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
LEASE_TIME=86400