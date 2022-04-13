# ipv4 packet sniffer
import socket
import binascii
import codecs
import datetime

# establish socket
host = socket.gethostbyname(socket.gethostname())                                
sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
sock.bind((host, 0))
sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

# prepare log file
name = datetime.datetime.now().strftime('ipv4_%Y-%m-%d_%H.%M.%S') + '.log'
out = open(name, 'ab')

# simultaneous file and console log
def log(text):
    try:
        data = bytes(text, 'utf-8')
    except:
        data = text
    try:
        print(codecs.decode(data, 'utf-8', 'ignore'))
    except:
        print(text)
    out.write(data + bytes('\n', 'utf-8'))

log(name + '\n')

while True:  
    # sniff datagram from network
    datagram = sock.recv(65535)
    raw = '0' + bin(int(binascii.hexlify(datagram), 16))[2:] 
    payload = int(raw[4:8], 2) * 4
    len = payload * 8

    # parse ipv4 header
    packet = {
        'VER' : (int(raw[0:4],2), 'Version'),
        'WRD ': (str(int(raw[4:8],2) * 4) + ' bytes', 'Header Length'),
        'TOS' : (int(raw[8:14],2), 'Type of Service'),
        'CNG' : (raw[14:16], 'Congestion'),
        'LEN' : (str(int(raw[16:32],2) * 4) + ' bytes', 'Packet Length'),
        'FRG' : (int(raw[32:48],2), 'Fragment Number'),
        'FLG' : (raw[48:51], 'Flags'),
        'OFF' : (int(raw[51:64],2), 'Fragment Offset'),
        'TTL' : (int(raw[64:72],2), 'Time to Live'),
        'PRO' : (int(raw[72:80],2), 'Data Protocol'),
        'CHK' : (raw[80:96], 'Checksum'),
        'SRC' : (str(int(raw[96:104],2)) + '.' + str(int(raw[104:112],2)) + '.' + str(int(raw[112:120],2)) + '.' + str(int(raw[120:128],2)), 'Source IP'),
        'DST' : (str(int(raw[128:136],2)) + '.' + str(int(raw[136:144],2)) + '.' + str(int(raw[144:152],2)) + '.' + str(int(raw[152:160],2)), 'Destination IP'),
        'OPT' : (raw[160:len], 'Options'),
    }

    # parse transmission protocol headers
    if packet['PRO'][0] is 17: # UDP
        payload += 8
        protocol = {
            'PRO' : ('UDP', 'Protocol'),
            'SRC' : (int(raw[len:len+16], 2), 'Source Port'),
            'DST' : (int(raw[len+16:len+32], 2), 'Destination Port'),
            'LEN' : (str(int(raw[len+32:len+48], 2) * 4) + ' bytes', 'Packet Length'),
            'CHK' : (raw[len+48:len+64], 'Checksum')
        }
    elif packet['PRO'][0] is 6: #TCP
        payload += int(raw[len+96:len+100], 2) * 4
        protocol = {
            'PRO' : ('TCP', 'Protocol'),
            'SRC' : (int(raw[len:len+16], 2), 'Source Port'),
            'DST' : (int(raw[len+16:len+32], 2), 'Destination Port'),
            'SEQ' : (int(raw[len+32:len+64], 2), 'Sequence Number'),
            'ACK' : (int(raw[len+64:len+96], 2), 'Acknowledgement'),
            'WRD' : (str(int(raw[len+96:len+100], 2) * 4) + ' bytes', 'Header Length'),
            'RSV' : (raw[len+100:len+103], 'Reserved Field'),
            'FLG' : (raw[len+103:len+112], 'Flags'),
            'WIN' : (str(int(raw[len+112:len+128], 2)) + ' bytes', 'Window Size'),
            'CHK' : (raw[len+128:len+144], 'Checksum'),
            'URG' : (raw[len+144:len+160], 'Urgent Pointer'),
            'OPT' : (raw[len+160:len + int(raw[len+96:len+100],2) * 32], 'Options')
        }
    else:
        protocol = { 'PRO' : ('OTHER', 'Protocol') }

    # log headers and payload of the packet
    for data in packet:
        value, desc = packet[data]
        log(desc.rjust(16, ' ') + ' : ' + str(value))

    log(''.ljust(40, '-'))

    for data in protocol:
        value, desc = protocol[data]
        log(desc.rjust(16, ' ') + ' : ' + str(value))

    log(''.ljust(40, '-'))
    log(datagram[payload:])
    log(''.ljust(80, '='))
    