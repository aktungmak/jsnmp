#!/usr/bin/python
#Version 1.0
#now has set requests!

import socket, struct
import datetime

class jsnmp:
    def __init__(self):
        self.payload = None
        self.decodeList = []
        self.OIDforcgi = ''

    def processIntPayload(self, start):
        #0x02
        result = 0
        more = 0
        length = ord(self.payload[start])
        if (length & 128):
            more = length & 127
            length = 0
            for i in range(1, more+1):
                shift = (more - i) * 7
                length += ord(self.payload[start+i]) << shift
        else:
            length &= 127
        #int specific from here
        for i in range(1, length+1):
            shift = (length - i) * 8
            result += ord(self.payload[start+more+i]) << shift
        self.decodeList.append(result)
        return length+more+1

    def processOctetStrPayload(self, start):
        #0x04
        result = ''
        more = 0
        length = ord(self.payload[start])
        if (length & 128):
            more = length & 127
            length = 0
            for i in range(1, more+1):
                shift = (more - i) * 7
                length += ord(self.payload[start+i]) << shift
        else:
            length &= 127
        #octstr specific from here
        result = self.payload[start+more+1:start+more+length+1]
        self.decodeList.append(result)
        return length+more+1

    def processOIDPayload(self, start):
        #0x06
        result = []
        more = 0
        length = ord(self.payload[start])
        if (length & 128):
            more = length & 127
            length = 0
            for i in range(1, more+1):
                shift = (more - i) * 7
                length += ord(self.payload[start+i]) << shift
        else:
            length &= 127
        #give this to getnext
        self.OIDforcgi = self.payload[start+more+1:start+more+length+1]
        #OID specific from here
        result.append(ord(self.payload[start+more+1]) / 40)
        result.append(ord(self.payload[start+more+1]) % 40)
        
        i = 2
        while i < length+1:
            if ord(self.payload[start+more+i]) & 128:
                #two byte
                x = ((ord(self.payload[start+more+i]) & 127) << 7) + ord(self.payload[start+more+i+1])
                result.append(x)
                i += 1
            else:
                #single byte
                result.append(ord(self.payload[start+more+i]))
            i += 1
        self.decodeList.append('.'.join(map(str, result)))
        return length+more+1

    def processSequence(self, start):
        #0x30
        more = 0
        length = ord(self.payload[start])
        if (length & 128):
            more = length & 127
            length = 0
            for i in range(1, more+1):
                shift = (more - i) * 7
                length += ord(self.payload[start+i]) << shift
        else:
            length &= 127
        self.decode(start+more+1, start+more+length+1)
        return length+more+1

    def processIPaddrPayload(self, start):
        # length should be 4
        length = ord(self.payload[start])

        result = []

        for i in range(1, length+1):
            result.append(str(ord(self.payload[start+i])))
        self.decodeList.append('.'.join(result))
        return length+1

        
    def processNullPayload(self, start):
        #0x05
        self.decodeList.append(None)
        return 1

    def processTimeticksPayload(self, start):
        #0x43
        result = 0
        more = 0
        length = ord(self.payload[start])
        if (length & 128):
            more = length & 127
            length = 0
            for i in range(1, more+1):
                shift = (more - i) * 7
                length += ord(self.payload[start+i]) << shift
        else:
            length &= 127
        #timeticks specific from here
        for i in range(1, length+1):
            shift = (length - i) * 8
            result += ord(self.payload[start+more+i]) << shift
        result = result // 100
        result = datetime.timedelta(seconds=result)

        self.decodeList.append(str(result))
        return length+more+1
        
    def decode(self, next=0, end=0):
        self.decodeList = []
        if not end:
            end = len(self.payload)
        #print self.payload[next:end]
        while next < end:
            type = self.payload[next]
            next += 1
            if type == '\x02':
                #print "integer"
                next += self.processIntPayload(next)
            elif type == '\x04':
                #print "octet string"
                next += self.processOctetStrPayload(next)
            elif type == '\x05':
                #print "NULL"
                next += self.processNullPayload(next)
            elif type == '\x06':
                #print "OID"
                next += self.processOIDPayload(next)
            elif type == '\x30':
                #print "sequence"
                next += self.processSequence(next)
            elif type == '\x40':
                #print "ipaddress"
                next += self.processIPaddrPayload(next)
            elif type == '\x43':
                #print "timeticks"
                next += self.processTimeticksPayload(next)
            else:
                pass

    def encodeGetPayload(self, oidStr, getNext=False):
        #this could be way faster if i concatenate all the bits
        #first do oid + null
        if getNext: pduType = '\xa1' 
        else:       pduType = '\xa0'

        payld = ''
        oidStr = map(int, oidStr.split('.')[2:])
        payld += '\x2b'
        for x in oidStr:
            if x > 255:
                payld += chr(128 + ((x & 2080768) >> 14))
                payld += chr(128 + ((x & 16256) >> 7))
                payld += chr(x & 127)
            elif x > 127:
                payld += chr(128 + ((x & 32640) >> 7))
                payld += chr(x & 127)
            else:
                payld += chr(x)
        payld = '%s%s%s%s' % ('\x06', chr(len(payld)), payld, '\x05\x00')
        #then do 30 chr(len(oid+null))
        payld = '%s%s%s' % ('\x30', chr(len(payld)), payld)
        #then 30 chr(len(oids)
        payld = '\x30' + chr(len(payld)) + payld
        #tack on two 020100 for no error
        payld = '\x02\x01\x00\x02\x01\x00' + payld
        #requestid of 020201d7 (471)
        payld = '\x02\x02\x01\xd7' + payld
        #then pdu, a1 len(pdu)
        payld = pduType + chr(len(payld)) + payld
        #community, 0406 public
        #version1 020100
        payld = '\x02\x01\x00\x04\x06public' + payld
        #at last, 30 len(payload)
        payld = '\x30' + chr(len(payld)) + payld
        return payld

    def encodeSetPayload(self, oidStr, payload_type, value):
        #this is basically the same as encodeGetPayload
        #first do oid + null
        #0: INT 1: OCTETSTR
        if payload_type == 0:
            value = '\x02\x04' + struct.pack('>i', value)
        elif payload_type == 1:
            value = '\x04' + chr(len(value)) + value

        pduType = '\xa3'

        payld = ''
        oidStr = map(int, oidStr.split('.')[2:])
        payld += '\x2b'
        for x in oidStr:
            if x > 255:
                payld += chr(128 + ((x & 2080768) >> 14))
                payld += chr(128 + ((x & 16256) >> 7))
                payld += chr(x & 127)
            elif x > 127:
                payld += chr(128 + ((x & 32640) >> 7))
                payld += chr(x & 127)
            else:
                payld += chr(x)
        payld = '%s%s%s%s' % ('\x06', chr(len(payld)), payld, value)
        #then do 30 chr(len(oid+null))
        payld = '%s%s%s' % ('\x30', chr(len(payld)), payld)
        #then 30 chr(len(oids)
        payld = '\x30' + chr(len(payld)) + payld
        #tack on two 020100 for no error
        payld = '\x02\x01\x00\x02\x01\x00' + payld
        #requestid of 020201d7 (471)
        payld = '\x02\x02\x01\xd7' + payld
        #then pdu, a1 len(pdu)
        payld = pduType + chr(len(payld)) + payld
        #community, 0406 private
        #version1 020100
        payld = '\x02\x01\x00\x04\x07private' + payld
        #at last, 30 len(payload)
        payld = '\x30' + chr(len(payld)) + payld
        return payld
        
    def snmpRequest(self, ipAddr, oid, getNext=False):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2)
            s.connect((ipAddr, 161))
            payld = self.encodeGetPayload(oid, getNext)
            s.sendall(payld)
            reply, addr = s.recvfrom(1084)
            s.close()
            self.payload = reply
        
        except socket.error, e:
            #print "Error: %s" % e
            self.payload = None

    def snmpSetRequest(self, ipAddr, oid, value, typ=0):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2)
            s.connect((ipAddr, 161))
            payld = self.encodeSetPayload(oid, typ, value)
            s.sendall(payld)
            reply, addr = s.recvfrom(1084)
            s.close()
            self.payload = reply
        
        except socket.error, e:
            #print "Error: %s" % e
            self.payload = None

    def listenForTrap(self):
        #listen for a trap to come in, block until then
        #return ip address that sent trap, actual data is in self.payload
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('', 500))
            #s.listen(0)
            reply, addr = s.recvfrom(1084)
            s.close()
            self.payload = reply
            print reply        
        #except socket.error as e:
            #print "Error: %s" % e
            #self.payload = None
        except KeyboardInterrupt:
            pass

if __name__ == '__main__':
    ipAddr = '192.168.44.43'
    p = jsnmp()

    #get example
    p.snmpRequest(ipAddr, '1.3.6.1.2.1.1.3.0', getNext=False)
    if p.payload:
        p.decode()
        print p.decodeList
        print p.decodeList[-1]

    #set example    
    p.snmpSetRequest(ipAddr, '1.3.6.1.4.1.1773.1.1.1.7.0', -90, 0)
    if p.payload:
        p.decode()
        print p.decodeList
        print p.decodeList[-1]

    #trap listener
    p = jsnmp()
    p.listenForTrap()
