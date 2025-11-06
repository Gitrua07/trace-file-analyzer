def parseDatagram():
    """
    parseDatagram(): Parses the provided cap file
    """
    print("PArsing...")

def getTrace():
    """
    getTrace(): Prints trace file information

    return:
    output: A string containing the trace file information
    """
    output = ''

    output+= f'The IP address of the ultimate source node: \n'    
    output+= f'The IP address of the ultimate destination node: \n'
    output+= f'The IP addresses of the intermediate destination nodes: \n \n \n'
    output+= f'The values in the protocol field of IP headers: \n \n \n'
    output+= f'The number of fragments created from the original datagram is: \n'
    output+= f'The offset of the last fragment is: \n\n'

    return output

def main() -> None:
    print(getTrace())

if __name__ == "__main__":
    main()