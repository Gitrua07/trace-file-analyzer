import struct
import sys
import IPPacket

#Class initializes packet field values
class Packet:
    def __init__(self, ts_sec, ts_usec, packet, raw_bytes):
        self.ts_sec = ts_sec
        self.ts_usec = ts_usec
        self.packet = packet              
        self.raw = raw_bytes             
        self.ip_header = raw_bytes[:packet.header_length]  
        self.payload = packet.payload     
        self.src_addr = packet.src_ip
        self.dest_addr = packet.dst_ip
        self.protocol = packet.protocol
        self.src_port, self.dst_port = self.get_port()
        self.ttl = self.ip_header[8]
        self.icmp_payload = packet.payload
        self.original_ip_header = self.icmp_payload[8:28]
        self.icmp_ttl = self.original_ip_header[8]

    def get_port(self):
        return struct.unpack('!HH', self.payload[:4])

def parseData(packets):
    """
    Initializes packet fields into list 

    Returns:
        datagrams: a list of packets that are Packet objects
    """
    datagrams = []
    for packet in packets:
        ts_sec, ts_usec, ip_packet, raw_bytes = packet
        temp = Packet(ts_sec, ts_usec, ip_packet, raw_bytes)
        datagrams.append(temp)
    return datagrams


def getCapFile(file):
    """
    Parses cap file provided by PCAP_FILE

    Returns:
        ip_packet_list: list of (ts_sec, ts_usec, IPPacket)
    """
    ip_packet_list = []

    with open(file, 'rb') as f:
        global_header = f.read(24)
        if len(global_header) < 24:
            print("Incomplete global header")
            exit(1)

        # Endianness from magic number
        magic_big = struct.unpack('>I', global_header[:4])[0]
        magic_little = struct.unpack('<I', global_header[:4])[0]

        if magic_big in (0xa1b2c3d4, 0xa1b23c4d):
            endian = '>'
        elif magic_little in (0xa1b2c3d4, 0xa1b23c4d):
            endian = '<'
        else:
            print("Unknown magic number, cannot determine endianness")
            exit(1)

        
        link_type = struct.unpack(f'{endian}I', global_header[20:24])[0]

        if link_type == 1:          
            ip_start = 14
        elif link_type == 101:     
            ip_start = 0
        else:
            print("Unsupported link type", link_type)
            exit(1)

        while True:
            packet_header = f.read(16)
            if len(packet_header) < 16:
                break

            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                f'{endian}IIII', packet_header
            )

            packet_data = f.read(incl_len)
            if len(packet_data) < incl_len:
                print("Incomplete packet data — skipping frame")
                continue

            if link_type == 1 and len(packet_data) < 14:
                continue

            if link_type == 1:
                ethertype = struct.unpack('!H', packet_data[12:14])[0]
                if ethertype != 0x0800:
                    continue

            ip_data = packet_data[ip_start:]

            if len(ip_data) < 20:
                continue

            version = ip_data[0] >> 4
            if version != 4:
                continue

            ip_packet = IPPacket.IPPacket.from_bytes(ip_data)
            ip_packet_list.append((ts_sec, ts_usec, ip_packet, ip_data))

    return ip_packet_list

def getTrace(datagrams, fragCount, rttCount, IntDests):
    """
    getTrace(): Prints trace file information

    return:
    output: A string containing the trace file information
    """
    frag_count = fragCount[0]
    last_offset = fragCount[1]
    src_addr = datagrams[0].src_addr
    dst_addr = datagrams[0].dest_addr
    output = ''

    output+= f'The IP address of the ultimate source node: {src_addr}\n'    
    output+= f'The IP address of the ultimate destination node: {dst_addr}\n'
    
    #Outputs the intermediate destination nodes
    output+= f'The IP addresses of the intermediate destination nodes: \n'
    counter = 1
    for k, ip in sorted(IntDests.items()):
        for x in range(0, len(ip)):
            output+= f'router {counter}: {ip[x]} (TTL={k})\n'
            counter += 1

    #Outputs the values of the protocol fields
    output+= f'\nThe values in the protocol field of IP headers: \n'
    protocol = []
    for datagram in datagrams:
        if datagram.protocol in protocol:
            continue
        if datagram.protocol == 1:
            output+= f'1: ICMP\n'
            protocol.append(1)
        if datagram.protocol == 17:
            output+= f'17: UDP\n'
            protocol.append(17)
    
    #Outputs fragment information
    output+= f'\nThe number of fragments created from the original datagram is: {frag_count}\n'
    output+= f'\nThe offset of the last fragment is: {last_offset}\n\n'

    #Outputs rtt and sd average between ip addresses
    sorted_rtt = sorted(rttCount.items())
    rtt_avgs = []
    hop_rtt = {}
    for hop, list_rtt in sorted_rtt:
        rtt_row = []
        dest_ip = list_rtt[0][0]

        for ip, rtt in list_rtt:
            rtt_row.append(rtt)

        rtt_avg = sum(rtt_row)/len(rtt_row)
        rtt_avgs.append(rtt_avg)
        
        if len(rtt_row) > 1:
            mean = rtt_avg
            variance = sum((x - mean) ** 2 for x in rtt_row) / len(rtt_row)
            sd = variance ** 0.5
        else:
            sd = 0.0
        
        hop_rtt[hop] = rtt_avg
        output += f"The avg RTT between {src_addr} and {dest_ip} is: {rtt_avg:.6f} ms, the s.d. is: {sd:.6f} ms\n"
    
    #Outputs trace and hop table
    output+= f"\n{'TTL':<5}{'Average RTT in this Trace File (ms)':>10}\n"
    for hop, rtt in hop_rtt.items():
        output+= f"{hop:<5}{rtt:>10.2f}\n"

    return output

def getIntDest(datagrams):
    """
    Determines the number of intermediate destination addresses and obtains
    address and rtt count by finding outgoing packets and getting their
    ttl.

    Returns:
        int_addrs: A dict of intermediate address sorted by hop numbers
        rttCount: A dict of rtt count sorted by hop numbers and containing
        the ip address and rtt count
    """
    int_addrs = {}
    rttCount = {}

    my_ip = None
    for p in datagrams:
        #Checks to see if the packet is UDP
        if p.protocol == 17:  
            my_ip = p.src_addr
            break

    if my_ip is None:
        return (int_addrs, rttCount) 

    probes_by_dstport = {}

    for packet in datagrams:
        #Outgoing UDP traceroute probe
        if packet.protocol == 17 and packet.src_addr == my_ip:
            if len(packet.payload) < 4:
                continue
            srcp, dstp = struct.unpack("!HH", packet.payload[:4])
            probes_by_dstport[dstp] = packet


    for packet in datagrams:

        if packet.protocol != 1:
            continue

        icmp_type = packet.payload[0]

        #Checking if the ICMP is returning the time-exceeded
        if icmp_type != 11:
            continue
        
        #Length of ip header
        ihl = (packet.icmp_payload[8] & 0x0F) * 4
        #Where udp header begins
        udp_offset = 8 + ihl

        #Contains udp header
        udp_header = packet.icmp_payload[udp_offset : udp_offset + 8]

        src_udp_p, dst_udp_p = struct.unpack("!HH", udp_header[:4])

        if dst_udp_p not in probes_by_dstport:
            continue
        
        #Obtains outgoing packet
        probe = probes_by_dstport[dst_udp_p]

        hop = probe.ttl                   
        router_ip = packet.src_addr        

        #Calculates rtt time
        send_time = probe.ts_sec + probe.ts_usec / 1e9
        recv_time = packet.ts_sec + packet.ts_usec / 1e9
        rtt = (recv_time - send_time) * 1000 

        if hop not in rttCount:
            rttCount[(hop)] = []
        rttCount[hop].append((router_ip, rtt))
        
        #Store intermediate address based on hops
        if hop not in int_addrs:
            int_addrs[hop] = [router_ip]
        elif router_ip not in int_addrs[hop]:
            int_addrs[hop].append(router_ip)

    return (int_addrs, rttCount)
                    
            
def getFragments(datagrams):
    """
    Calculates the number of fragments in the datagram

    Returns:
        num_frags: Number of fragments in the datagram
        last_offset: Last offset of the last fragment
    """
    fragment_map = {}
    timestamps = []

    for d in datagrams:
        ip_header = d.ip_header
        if len(ip_header) < 8:
            continue

        ident = struct.unpack('!H', ip_header[4:6])[0]

        flags_and_offset = struct.unpack('!H', ip_header[6:8])[0]
        fragment_offset = flags_and_offset & 0x1FFF
        mf_flag = flags_and_offset & 0x2000

        #Detect outer fragments only
        if mf_flag or fragment_offset > 0:
            t = d.ts_sec + d.ts_usec / 1_000_000
            timestamps.append((ident, t, d.src_addr, d.dest_addr))
            fragment_map.setdefault(ident, []).append((fragment_offset, mf_flag))

    if not fragment_map:
        return (0, 0, [])

    #Find the packet with the most fragments
    ident = max(fragment_map, key=lambda k: len(fragment_map[k]))
    frag_list = fragment_map[ident]

    num_frags = len(frag_list)
    last_offset = max(offset for offset, mf in frag_list)

    return (num_frags, last_offset) 

def main() -> None:
    #Initalize file input
    file = sys.argv[1]
    #Obtains packet from file
    packet = getCapFile(file)
    #Parses packet
    datagrams = parseData(packet) 
    #Obtains Intermediate Destination Address and rtt count
    IntDests, rttCount = getIntDest(datagrams)
    #Obtains the number of fragments in the datagram
    fragCount = getFragments(datagrams)
    #Prints the trace information
    print(getTrace(datagrams, fragCount, rttCount, IntDests))


if __name__ == "__main__":
    main()