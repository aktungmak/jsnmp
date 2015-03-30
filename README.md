# jsnmp
single file SNMP library written in pure python. 
simple, easy and lightweight to include in any project without external dependencies. the code is designed for readability rather than speed, though in practice it has been found to be very performant.

It currently supports:

- GETs
- GET-NEXTs
- SETs
- Basic trap listener

It knows about the following PDU types:

- __0x02__ integer
- __0x04__ octet string
- __0x05__ null
- __0x06__ oid
- __0x30__ sequence
- __0x40__ ipaddress
- __0x43__ timeticks

This covers every use case found so far, more will be added as they are discovered to be useful.
