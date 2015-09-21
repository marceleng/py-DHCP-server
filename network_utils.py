'''
Created on Dec 21, 2014

@author: Marcel Enguehard
'''
import re,struct,socket
from subprocess import Popen,PIPE

is_ip_prefix=re.compile("^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$")
is_ip=re.compile("^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$")
UDP_HEADER_LENGTH = 8
UDP_PSEUDOHEADER_LENGTH = 12
ETH_HEADER_SIZE = 14

transport_protocols = {
                       'ICMP' : '\x01',
                       'TCP' : '\x06',
                       'UDP' : '\x11'}

ether_types = {
               'IPv4' : "\x08\x00",
               'ARP' : '\x08\x06',
               'IPv6' : '\x86\xDD'}

'''
    Returns the boundaries in a IP prefix (eg "192.168.0.0/24" --> [192.168.0.0,192.168.0.255])
'''
def get_ip_pool_from_string(ip_pool):
    if is_ip_prefix.match(ip_pool) is None:
        raise ValueError("Input must be an IP prefix: "+ip_pool)
    ip = ip4_aton(ip_pool.split("/")[0])
    prefix = int(ip_pool.split("/")[1])
    return [ip4_ntoa(ip-(ip % (2**(32-prefix)))),ip4_ntoa(ip-(ip % (2**(32-prefix)))+2**(32-prefix)-1)]

'''
    Returns the subnet mask from a prefix (eg "192.168.0.0/24" --> "255.255.255.0")
'''
def get_subnet_mask_from_prefix(ip_prefix): 
    if is_ip_prefix.match(ip_prefix) is None:
        raise ValueError("Input must be an IP prefix: "+ip_prefix)
    prefix = int(ip_prefix.split("/")[1])
    '''
        Example: if prefix = 24, 2^(32-prefix)-1 = 0.0.0.255, then xor with 255.255.255.255 to inverse the bytes 
    '''
    return ip4_ntoa((2**(32-prefix)-1) ^ 0xffffffff) 

def get_broadcast_addr(ip_prefix):
    if is_ip_prefix.match(ip_prefix) is None:
        raise ValueError("Input must be an IP prefix: "+ip_prefix)
    ip = ip4_aton(ip_prefix.split("/")[0])
    prefix = int(ip_prefix.split("/")[1])
    ip = ip-(ip % (2**(32-prefix)))
    
    return ip4_ntoa(ip + 2**(32-prefix)-1)

def ip4_aton(ip_as_string):
    if is_ip.match(ip_as_string) is None:
        raise ValueError("Input must be an IP prefix: "+ip_as_string)
    return struct.unpack("!I", socket.inet_aton(ip_as_string))[0]

def ip4_ntoa(ip_as_uint):
    if ip_as_uint > (2**32-1):
        return None #TODO: Do smthg
    return socket.inet_ntoa(struct.pack("!I", ip_as_uint))

def get_next_ip(ip_pool,current_ip):
    ip_as_uint = ip4_aton(current_ip)
    min_bound,max_bound = map(ip4_aton,ip_pool)
    if ip_as_uint==max_bound:
        return min_bound
    else:
        return ip4_ntoa(ip_as_uint+1)

def double_zeros(s):
    if s=="0":
        return "00"
    else:
        return s

def mac_hextostr(hex_payload):
    return ":".join(map(double_zeros, map(lambda x : format(ord(x),"x"),hex_payload)))

def mac_strtohex(mac_as_str):
    try:
        return "".join(map(lambda x : chr(int(x,16)),mac_as_str.split(":")))
    except Exception:
        print("Failed mac_strtohex with "+mac_as_str)

'''
    Returns the mac address of the corresponding interface
'''
def get_nic_addr(nic):
    ifc = Popen(["ifconfig",nic],stdout=PIPE,stderr=PIPE)
    (stdout,_) = ifc.communicate()
    parsedOut = stdout.strip().split()
    isNext=False
    for s in parsedOut:
        if isNext:
            return s
        elif s.find("HWaddr") != -1:
            isNext = True
    return None

'''
    Creates a full UDP packet (including IP and Ethernet header) containing 'data'
'''
def create_UDP_packet(source_mac,dest_mac,source_ip,dest_ip,source_port,dest_port,data,udp_checksum=False,ip_ttl=64,ip_options=None,ip_id=0):
    
    udp_length = UDP_HEADER_LENGTH + len(data)
    
    ip_header_size = __get_ipv4_header_size(ip_options)
    packet = ["\x00"] * (udp_length+ip_header_size+ETH_HEADER_SIZE)
    start_udp = ETH_HEADER_SIZE+ip_header_size
    
    #Ethernet header
    packet[:ETH_HEADER_SIZE] = generate_eth_header(source_mac, dest_mac, "IPv4")
    #IP header
    packet[ETH_HEADER_SIZE:start_udp] = generate_ipv4_header(source_ip, dest_ip, "UDP", udp_length+ip_header_size, ip_ttl, ip_options, ip_id)
    #UDP header
    packet[start_udp:start_udp+UDP_HEADER_LENGTH] = generate_udp_header(packet[0:ip_header_size], source_port, dest_port, udp_length)
    #data
    packet[start_udp+UDP_HEADER_LENGTH:] = data
    
    if udp_checksum:
        packet[start_udp+6:start_udp+8] = struct.pack("!H",compute_UDP_checksum(packet[ETH_HEADER_SIZE:start_udp], packet[start_udp:]))
    
    return packet

def generate_eth_header(source_addr,dest_addr, eth_type):
    header = ["\x00"] * ETH_HEADER_SIZE
    header[0:6] = mac_strtohex(dest_addr)
    header[6:12] = mac_strtohex(source_addr)
    header[12:14] = ether_types[eth_type]
    return header

'''
Generates a IPv4 header
packet_size: size of the total packet (header included)
TODO:handle options + flags
'''
def generate_ipv4_header(source_ip,dest_ip,protocol,packet_size,ttl=64,options=None,identification=0):
    header_size=__get_ipv4_header_size(options) #header size in 32-bits words (TBM to handle options)
    
    header = ["\x00"] * header_size
    header[0] = chr((4<<4)+header_size/4) #IP version + header_size
    header[2:4] = struct.pack("!H",packet_size)
    header[4:6] = struct.pack("!H",identification)
    header[8] = chr(ttl)
    header[9] = transport_protocols[protocol]
    header[12:16] = socket.inet_aton(source_ip)
    header[16:20] = socket.inet_aton(dest_ip)
    header[10:12] = struct.pack("!H",__internet_checksum(header,header_size))
    return header

'''
Generates a UDP header but no checksum (the whole packet is needed for that)
length: length of the UDP packet (header+data)
'''
def generate_udp_header(ip_header,source_port,dest_port,length):
    header = ["\x00"] * UDP_HEADER_LENGTH
    header[0:2] = struct.pack("!H",source_port)
    header[2:4] = struct.pack("!H",dest_port)
    header[4:6] = struct.pack("!H",length)
    return header

'''
    Computes the UDP checksum of a full UDP packet
    TODO: Include support for IPv6?
'''
def compute_UDP_checksum(ip_header,packet):
    ip_version = struct.unpack("B",ip_header[0])[0] >> 4
    if ip_version == 6:
        raise NotImplementedError("IPv6 support not implemented yet")
    elif ip_version != 4:
        raise ValueError("IP version should be 4 or 6")
    
    udp_length = len(packet)
    #pseudo_packet has a pseudo header as specified in RFC 768: https://tools.ietf.org/html/rfc768
    pseudo_packet = ["\x00"] * (udp_length+UDP_PSEUDOHEADER_LENGTH)
    pseudo_packet[0:8] = ip_header[12:20] #Copies source and dest IP addresses
    pseudo_packet[9] = '\x11' #UDP protocol number
    pseudo_packet[10:12] = struct.pack("!H",udp_length)
    pseudo_packet[12:] = packet
    
    checksum =  __internet_checksum(pseudo_packet, udp_length+UDP_PSEUDOHEADER_LENGTH)
    if checksum==0: #As specified in RFC768, because a null checksum means no checksum
        return 0xffff
    else:
        return checksum

'''
    Returns the size in bytes of an IPv4 header. Right now only returns 20 (default size)
    TODO: add support for options
'''
def __get_ipv4_header_size(options):
    if options is not None:
        raise NotImplementedError("No support for IP options yet")
    else:
        return 20    

#Computes Internet checksum according to RFC1071: http://tools.ietf.org/html/rfc1071
def __internet_checksum(data,data_size):
    checksum = 0
    if data_size % 2 == 1:
        words=struct.unpack("!"+str(data_size/2+1)+"H",''.join(data)+"\x00")
    else:
        words=struct.unpack("!"+str(data_size/2)+"H",''.join(data))
    for word in words:
        checksum = __ones_complement_sum(checksum, word)
    return ~checksum & 0xffff
 

#Executes ones' complement sum of 16-bits words    
def __ones_complement_sum(a,b):
    if(a>2**16 or b>2**16):
        raise ValueError("Only 16 bits words tolerated in ones' complement sum")
    result = a+b
    return (result & 0xffff) + (result >> 16)
