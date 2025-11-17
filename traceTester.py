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
        ip_packet_list: Parsed cap file
    """
    #parse using struct
    ip_packet_list = []
    with open(file, 'rb') as f:
        #Reads TCP Header
        global_header = f.read(24) #Retrieves global header
        if len(global_header) < 24: #If global header is less than 24 bytes
            print("Incomplete global header")
            exit(1)
    
        #Finds if PCAP is big-endian or little-endian
        magic_big = struct.unpack('>I', global_header[:4])[0]
        magic_little = struct.unpack('<I', global_header[:4])[0]

        if magic_big == 0xa1b2c3d4 or magic_big == 0xa1b23c4d:
            endian = '>' #big-endian
        elif magic_little == 0xa1b2c3d4 or magic_little == 0xa1b23c4d:
            endian = '<' #little-endian
        else:
            print("Unnown magic number, cannot determine endianness")
            exit(1)

        #Reads packet header
        while True:
            packet_header = f.read(16)
            if len(packet_header) < 16:
                break

            #Retrieve header values
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f'{endian}IIII', packet_header)

            packet_data = f.read(incl_len)
            if len(packet_data) < incl_len:
                print("Incomplete packet data")
                break

            ip_packet = IPPacket.IPPacket.from_bytes(packet_data[14:])
            ip_packet_list.append((ts_sec, ts_usec, ip_packet))
    
    return ip_packet_list

def getTrace(datagrams, fragCount):
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
    output+= f'The IP addresses of the intermediate destination nodes: \n \n \n'
    output+= f'The values in the protocol field of IP headers: \n'
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
    output+= f'\nThe avg RTT between .. and .. is: .. ms, the s.d. is: .. ms \n'

    return output

def parseConnections(datagrams):
    """
    parseConnections: Establishes all connections in datagram

    Returns: A list of connections
    """
    connections = {}
    for datagram in datagrams:
        if datagram.protocol == 6 or datagram.protocol == 17:
            #TCP connection and UDP connection
            connection_to = (datagram.src_addr, datagram.src_port, datagram.dest_addr, datagram.dst_port)
            connection_from = (datagram.dest_addr, datagram.dst_port, datagram.src_addr, datagram.src_port)
        elif datagram.protocol == 1:
            continue
        #Work on this later
            #ICMP connection
            #print(datagram.payload.hex())
            ip_header_length = (datagram.payload[8] & 0x0F) * 4
            icmp_offset = 8 + ip_header_length
            icmp = datagram.payload[icmp_offset:icmp_offset+8]

            if len(icmp) < 8:
                continue

            icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq =\
                struct.unpack('!BBHHH', icmp[:8])
            connection_to = (datagram.src_addr, datagram.dest_addr, icmp_id + icmp_seq)
            connection_from = 0
            #connection_from = (datagram.src_addr, datagram.dest_addr, icmp_id + icmp_seq)
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
    for key, packets in connections.items():
        for packet in packets:
            if packet.protocol == 1:
                ip_header_length = (packet.payload[8] & 0x0F) * 4
                icmp_offset = 8 + ip_header_length
                icmp = packet.payload[icmp_offset:icmp_offset+8]
                icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq = struct.unpack('!BBHHH', icmp[:8])
                #print(icmp_type)
                if icmp_type == 11:
                    print("TIME EXCEEDED")
            
def getFragments(datagrams):
    frag_count = 0
    fragment_num = []
    last_offset = -1
    for datagram in datagrams:
        ip_header = datagram.payload[14:34]
        identification_bytes = ip_header[4:6]
        result = struct.unpack('!H', identification_bytes)[0]
        frag_field = datagram.payload[14 + 6: 14 + 8]
        flags_and_offset = struct.unpack("!H", frag_field)[0]
        fragment_offset = flags_and_offset & 0x1FFF

        if result not in fragment_num:
            fragment_num.append(result)
            frag_count += 1
        
        if result == 0 and fragment_offset != 0:
            last_offset = fragment_offset
            break

    return (frag_count, last_offset)

def main() -> None:
    file = sys.argv[1]
    packet = getCapFile(file)
    datagrams = parseData(packet)
    connections = parseConnections(datagrams)
    IntDests = getIntDest(connections)
    fragCount = getFragments(datagrams)
    print(getTrace(datagrams, fragCount))
    #for datagram in datagram_list:
     #   print(getTrace(datagram))


if __name__ == "__main__":
    main()