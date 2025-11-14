import struct
import sys
import IPPacket

class Datagram:
    def __init__(self, packet):
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
        temp = Datagram(pack)
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

def getTrace(datagram):
    """
    getTrace(): Prints trace file information

    return:
    output: A string containing the trace file information
    """
    src_addr = datagram.src_addr
    dst_addr = datagram.dest_addr
    output = ''

    output+= f'The IP address of the ultimate source node: {src_addr}\n'    
    output+= f'The IP address of the ultimate destination node: {dst_addr}\n'
    output+= f'The IP addresses of the intermediate destination nodes: \n \n \n'
    output+= f'The values in the protocol field of IP headers: \n \n \n'
    output+= f'The number of fragments created from the original datagram is: \n'
    output+= f'The offset of the last fragment is: \n\n'
    output+= f'The avg RTT between .. and .. is: .. ms, the s.d. is: .. ms \n'

    return output

def parsePackets(datagram):
    """
    self.packet = packet
        self.payload = packet.payload
        self.src_addr = packet.src_ip
        self.dest_addr = packet.dst_ip
        self.protocol = packet.protocol
        self.src_port, self.dst_port = self.get_port()
    """
    if datagram.protocol == 6 or datagram.protocol == 11:
        #TCP connection and UDP connection
        connection_to = (datagram.src_addr, datagram.src_port, datagram.dest_addr, datagram.dst_port)
        connection_from = (datagram.dest_addr, datagram.dst_port, datagram.src_addr, datagram.src_port)
    elif datagram.protocol == 1:
        #ICMP connection
        ip_header_length = (datagram.packet[0] & 0x0F) * 4
        icmp_offset = 14 + ip_header_length
        icmp = datagram.payload[icmp:icmp+8]
        icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq = struct.unpack('!BBHHH', icmp)
        connection_to = (datagram.src_addr, datagram.dest_addr, icmp_id + icmp_seq)
    else:
        print(f'Error: Protocol number unknown')
        exit(1)

    #connection_to = (datagram.)

def main() -> None:
    file = sys.argv[1]
    packet = getCapFile(file)
    datagram_list = parseData(packet)

    #for datagram in datagram_list:
     #   print(getTrace(datagram))


if __name__ == "__main__":
    main()