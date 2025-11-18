import struct
import sys
import IPPacket

class Packet:
    def __init__(self, ts_sec, ts_usec, packet):
        self.ts_sec = ts_sec
        self.ts_usec = ts_usec
        self.packet = packet
        self.payload = packet.payload
        self.src_addr = packet.src_ip
        self.dest_addr = packet.dst_ip
        self.protocol = packet.protocol
        self.src_port, self.dst_port = self.get_port()

    def get_port(self):
        return struct.unpack('!HH', self.payload[:4])

def parseData(packets):
    datagrams = []
    for packet in packets:
        pack = packet[2]
        ts_sec = packet[0]
        ts_usec = packet[1]
        temp = Packet(ts_sec, ts_usec, pack)
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
            ip_packet_list.append((ts_sec, ts_usec, ip_packet))

    return ip_packet_list

def getTrace(datagrams, fragCount, rttCount, IntDests, sdCount):
    """
    getTrace(): Prints trace file information

    return:
    output: A string containing the trace file information
    """
    frag_count = fragCount[0]
    last_offset = fragCount[1]
    src_addr = datagrams[0].src_addr
    dst_addr = datagrams[len(datagrams)-1].dest_addr
    output = ''

    output+= f'The IP address of the ultimate source node: {src_addr}\n'    
    output+= f'The IP address of the ultimate destination node: {dst_addr}\n'
    output+= f'The IP addresses of the intermediate destination nodes: \n'
    for x in range(0,len(IntDests)):
        output += f'router {x+1}: {IntDests[x]}\n'
    
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
    output+= f'\nThe number of fragments created from the original datagram is: {frag_count}\n'
    output+= f'\nThe offset of the last fragment is: {last_offset}\n\n'
    for key1,rtt in rttCount.items():
        avg = sum(rtt)/len(rtt)
        output+= f'\nThe avg RTT between {key1[0]} and {key1[1]} is: {avg} ms, the s.d. is: {sdCount[key1]} ms \n'

    return output

def parseConnections(datagrams):
    """
    parseConnections: Establishes all connections in datagram

    Returns: A list of connections
    """
    connections = {}
    rtt_time = {}
    for datagram in datagrams:
        if datagram.protocol == 6 or datagram.protocol == 17:
            #TCP connection and UDP connection
            connection_to = (datagram.src_addr, datagram.src_port, datagram.dest_addr, datagram.dst_port)
            connection_from = (datagram.dest_addr, datagram.dst_port, datagram.src_addr, datagram.src_port)
        elif datagram.protocol == 1:
            ip_header_length = (datagram.payload[8] & 0x0F) * 4
            icmp_offset = 8 + ip_header_length
            icmp = datagram.payload[icmp_offset:icmp_offset+8]

            if len(icmp) < 8:
                continue

            icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq =\
                struct.unpack('!BBHHH', icmp[:8])
            connection_to = (datagram.src_addr, datagram.dest_addr, icmp_id + icmp_seq)
            connection_from = 0
        elif datagram.protocol == 0:
            continue
        else:
            print(f'Error: Protocol number unknown')
            exit(1)

        if connection_to in connections:
            connections[connection_to].append(datagram)
        elif connection_from in connections:
            connections[connection_from].append(datagram)
        else:
            connections[connection_to] = [datagram]
    
    return connections

def getIntDest(connections):
    int_addrs = []
    T = 0
    for key, packets in connections.items():
        for packet in packets:
            if packet.protocol == 1:
                
                if len(packet.payload) < 8:
                    continue

                icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq = struct.unpack('!BBHHH', packet.payload[:8])
                if icmp_type == 11:
                    int_addr = packet.dest_addr
                    int_addrs.append(int_addr)
                    T = packet.ts_sec + packet.ts_usec / 1_000_000
    
    return (int_addrs, T)
                    
            
def getFragments(datagrams):
    frag_count = 0
    fragment_num = []
    last_offset = -1
    timesteps = []
    for datagram in datagrams:
        ip_header = datagram.payload[14:34]
        identification_bytes = ip_header[4:6]
        result = struct.unpack('!H', identification_bytes)[0]
        frag_field = datagram.payload[14 + 6: 14 + 8]
        flags_and_offset = struct.unpack("!H", frag_field)[0]
        fragment_offset = flags_and_offset & 0x1FFF

        if result not in fragment_num:
            time = datagram.ts_sec + datagram.ts_usec / 1_000_000
            timesteps.append((time, datagram.src_addr, datagram.dest_addr))
            fragment_num.append(result)
            frag_count += 1
        
        if result == 0 and fragment_offset != 0:
            last_offset = fragment_offset
            break

    return (frag_count, last_offset, timesteps)

def getRTT(connections):
    probe_send_times = {}
    rtt_list = {}

    for key, packets in connections.items():
        for p in packets:
            if p.protocol in (17, 6):

                probe_key = (p.src_addr, p.src_port,
                             p.dest_addr, p.dst_port)

                send_time = p.ts_sec + p.ts_usec / 1e6
                probe_send_times[probe_key] = send_time

        for p in packets:
            if p.protocol == 1:  

                icmp_type = p.payload[0]
                if icmp_type not in (11, 3):
                    continue

                icmp_payload = p.payload
                if len(icmp_payload) < 36:
                    continue  

                orig_ip = icmp_payload[8:28]
                orig_udp = icmp_payload[28:36]

                orig_src_ip = f"{orig_ip[12]}.{orig_ip[13]}.{orig_ip[14]}.{orig_ip[15]}"
                orig_dst_ip = f"{orig_ip[16]}.{orig_ip[17]}.{orig_ip[18]}.{orig_ip[19]}"
                orig_src_port, orig_dst_port = struct.unpack("!HH", orig_udp[:4])

                probe_key = (orig_src_ip, orig_src_port,
                             orig_dst_ip, orig_dst_port)

                if probe_key not in probe_send_times:
                    continue 

                send_time = probe_send_times[probe_key]
                recv_time = p.ts_sec + p.ts_usec / 1e6
                rtt = recv_time - send_time

                router_ip = (p.src_addr, p.dest_addr)
                rtt_list.setdefault(router_ip, []).append(rtt)

    return rtt_list

def getSD(rttCount):
    sd_list = {}
    for key, rtt in rttCount.items():
        m = sum(rtt)/len(rtt)
        variance = sum((x-m) ** 2 for x in rtt)/len(rtt)
        sd = variance ** 0.5
        sd_list[key] = sd

    return sd_list
    


def main() -> None:
    file = sys.argv[1]
    packet = getCapFile(file)
    datagrams = parseData(packet)
    connections = parseConnections(datagrams)
    IntDests, T = getIntDest(connections)
    fragCount = getFragments(datagrams)
    rttCount = getRTT(connections)
    sdCount = getSD(rttCount)
    print(getTrace(datagrams, fragCount, rttCount, IntDests, sdCount))


if __name__ == "__main__":
    main()