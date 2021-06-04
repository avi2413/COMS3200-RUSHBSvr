import socket
import struct
import os
import math
import subprocess

HEADER = 64
SEQUENCE = 16
ACK = 32
CKS = 48
PACKET_SIZE = 1472
PAYLOAD_SIZE = 1464

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('127.0.0.1', 60000))

print(sock.getsockname()[1], flush=True)

packetSent = 0
estPackets = 0
msg_dict = dict()
ctr = 0
seq_ctr = 0
ack_ctr = 0
while True:
    message = bytearray()
    packet = None
    try:
        sock.settimeout(4.0)
        packet, addr = sock.recvfrom(PACKET_SIZE)
        seq, ack_no, chk, flag = struct.unpack('!H H H H', packet[0:8])
        
        if flag == 8194: # [GET] flag
            ctr+=1
            print('[', ctr, '] ', 'in line', 31)
            fileName = './'+str(packet[8:].decode('utf-8')).replace('\0', '')
            fileSize = os.path.getsize(fileName)
            # print(fileName)
            # print('File Size: ', fileSize)
            estPackets = math.ceil(fileSize/PAYLOAD_SIZE)
            # print('Est. Packets reqd: ', estPackets)
            try:
                f = open(fileName, 'rb')
            except IOError:
                continue
            if fileSize <= PAYLOAD_SIZE:
                seq_ctr += 1
                seq = seq_ctr
                seq = struct.pack('!H', seq)
                ack_no = 0
                ack_no = struct.pack('!H', ack_no)
                chk = struct.pack('!H', chk)
                flag = 2050 #[FIN]
                flag = struct.pack('!H', flag)
                for i in seq:
                    message.append(i)
                for i in ack_no:
                    message.append(i)
                for i in chk:
                    message.append(i)
                for i in flag:
                    message.append(i)
                payload = f.read(PAYLOAD_SIZE)
                for x in payload:
                    message.append(x)
                if len(bytes(message)) != PACKET_SIZE:
                    for i in range(PACKET_SIZE - len(bytes(message))):
                        message.append(0x00)
                msg_dict[seq] = message
            else:
                i = 0
                buff = bytearray()
                for x in f.read(PAYLOAD_SIZE):
                    buff.append(x)
                    i=i+1
                    if (i == PAYLOAD_SIZE):
                        #tranmit packet with DAT
                        seq_ctr += 1
                        seq = seq_ctr 
                        seq = struct.pack('!H', seq)
                        ack_no = 0
                        ack_no = struct.pack('!H', ack_no)
                        chk = struct.pack('!H', chk)
                        flag = 4098
                        flag = struct.pack('!H', flag)
                        for i in seq:
                            message.append(i)
                        for i in ack_no:
                            message.append(i)
                        for i in chk:
                            message.append(i)
                        for i in flag:
                            message.append(i)
                        for x in buff:
                            message.append(x)
                        i = 0
                        msg_dict[seq] = message
                        packetSent += 1
                        continue
        elif flag == 36866 and packetSent != estPackets : #[ACK/DAT]
            ctr +=1
            print('[', ctr, '] ', 'in line', 91)
            # print('In [ACK/DAT]: ', fileName)
            f = open(fileName, 'rb')
            f.seek(PAYLOAD_SIZE*packetSent)
            ack_no = 0
            payload = f.read(PAYLOAD_SIZE)
            seq_ctr += 1
            seq = seq_ctr 
            seq = struct.pack('!H', seq)
            ack_no = struct.pack('!H', ack_no)
            chk = struct.pack('!H', chk)
            flag = 4098 #[DAT]
            for i in seq:
                message.append(i)
            for i in ack_no:
                message.append(i)
            for i in chk:
                message.append(i)
            flag = struct.pack('!H', flag)
            for i in flag:
                message.append(i)
            # if not the last packet
            if packetSent != estPackets-1:
                # flag = 4098 #[DAT]
                # for i in seq:
                #     message.append(i)
                # for i in ack_no:
                #     message.append(i)
                # for i in chk:
                #     message.append(i)
                # flag = struct.pack('!H', flag)
                # for i in flag:
                #     message.append(i)
                for x in payload:
                    message.append(x)
                msg_dict[seq] = message
                packetSent += 1
            else: #Last packet
                # flag = 2050 #[FIN]
                # for i in seq:
                #     message.append(i)
                # for i in ack_no:
                #     message.append(i)
                # for i in chk:
                #     message.append(i)
                # flag = struct.pack('!H', flag)
                # for i in flag:
                #     message.append(i)
                for x in payload:
                    message.append(x)
                if len(bytes(message)) != PACKET_SIZE:
                    for i in range(PACKET_SIZE-len(bytes(message))):
                        message.append(0x00) 
                msg_dict[seq] = message
                packetSent += 1  
        elif packetSent == estPackets: # Last [FIN]
            ctr+=1
            print('[', ctr, '] ', 'in line', 146)
            flag = 2050
            ack_no = 0
            seq_ctr += 1
            seq = seq_ctr 
            seq = struct.pack('!H', seq)
            ack_no = struct.pack('!H', ack_no)
            chk = struct.pack('!H', chk)
            flag = struct.pack('!H', flag)
            for i in seq:
                message.append(i)
            for i in ack_no:
                message.append(i)
            for i in chk:
                message.append(i)
            for i in flag:
                message.append(i)
            for i in range(PAYLOAD_SIZE):
                message.append(0x00)
            msg_dict[seq] = message
            packetSent += 1
        elif flag == 20482: #[DAT/NAK]
            ctr+=1
            print('[', ctr, '] ', 'in line', 167)
            message = msg_dict[struct.pack('!H', ack_no)]
            # sock.sendto(bytes(msg_dict[struct.pack('!H', ack_no)]), addr)
        elif flag == 34818: #Last [FIN/ACK]
            ctr+=1
            print('[', ctr, '] ', 'in line', 171)
            flag = 34818
            ack = seq
            #ack_no += 1
            seq_ctr += 1
            seq = seq_ctr 
            seq = struct.pack('!H', seq)
            ack_no = struct.pack('!H', ack)
            chk = struct.pack('!H', chk)
            flag = struct.pack('!H', flag)
            for i in seq:
                message.append(i)
            for i in ack_no:
                message.append(i)
            for i in chk:
                message.append(i)
            for i in flag:
                message.append(i)
            for i in range(PAYLOAD_SIZE):
                message.append(0x00)
            msg_dict[seq] = message
        else: 
            #close the connection
            flag = 2050
            seq = 0
            ack = 0
            seq = struct.pack('!H', seq)
            ack_no = struct.pack('!H', ack)
            chk = struct.pack('!H', chk)
            flag = struct.pack('!H', flag)
            for i in seq:
                message.append(i)
            for i in ack_no:
                message.append(i)
            for i in chk:
                message.append(i)
            for i in flag:
                message.append(i)
            for i in range(PAYLOAD_SIZE):
                message.append(0x00)

        sock.sendto(bytes(message), addr)
    
    except KeyboardInterrupt:
        sock.close()
