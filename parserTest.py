from scapy.all import *
def expand(x):
    yield x.name
    while x.payload:
        x = x.payload
        yield x.name

def parsePacket(packet):
	global i
	No=i+1
	if (packet.haslayer(ARP)):
            if packet.op == 1:
                #request
                if((packet.psrc == packet.pdst) and (packet.hwdst == "00:00:00:00:00:00")):
                    info = '{}{}{}'.format("Gratuitous ARP for ", packet.psrc, " (Request)")
                else:
                    info =  '{}{}{}{}'.format("Who has ", packet.pdst, "? Tell ", packet.psrc)
            elif packet.op == 2:
                #response
                info =  '{}{}{}'.format(packet.psrc, " is at ", packet.hwsrc)
                #unknown
            else:
                info = "Unknown op"

            print('{:>8}  {:>8} {} {:<50}'.format(No, "ARP",5*" ", info))

	elif (packet.haslayer(LLMNRQuery) or packet.haslayer(LLMNRResponse)):
                info = packet.summary()
                #info = "llmnr info"
                print('{:>8}  {:>8} {} {:<50}'.format(No, "LLMNR",5*" ", info))

	elif (packet.haslayer(NBNSQueryRequest) or packet.haslayer(NBNSQueryResponse)):
                info = packet.summary()
                #info = "nbns info"
                print('{:>8}  {:>8} {} {:<50}'.format(No, "NBNS",5*" ", info))

	elif (packet.haslayer(DNS)):
            if (packet.qr == 0):
                #request
                RespOrQuery = "query "
                if (packet.opcode == 0):
                    opcodeQuery = "Standard "
                elif (packet.opcode == 1):
                    opcodeQuery = "Inverse "
                elif (packet.opcode == 2):
                    opcodeQuery = "Status "
                elif (packet.opcode == range(3,16)):
                    opcodeQuery = "Reserved "
                else:
                    opcodeQuery = "(Unknown opcode) "
                info =  '{}{}{}{}{}'.format(opcodeQuery, RespOrQuery, hex(packet.getlayer(DNS).id), " A " if packet.qd.qtype == 1 else" Not A ", packet.qd.qname.decode()[:-1])
            elif packet.qr == 1:
                #response
                RespOrQuery = "Response"
                info =  '{}'.format(RespOrQuery)
                #unknown
            else:
                info = "(Unknown qr)"

            print('{:>8}  {:>8} {} {:<50}'.format(No, "DNS",5*" ", info))

	elif (packet.haslayer(STP)):
                info = packet.summary()
                print('{:>8}  {:>8} {} {:<50}'.format(No, "STP",5*" ", info))

	elif (packet.haslayer(DHCP)):
                info = packet.summary()
                print('{:>8}  {:>8} {} {:<50}'.format(No, "DHCP",5*" ", info))
	elif (packet.haslayer(IPv6) and packet.haslayer(UDP) and "DHCP" in packet.summary()):
                info = packet.summary()
                print('{:>8}  {:>8} {} {:<50}'.format(No, "DHCPv6",5*" ", info))

	elif (packet.haslayer(IPv6) and packet.getlayer(IPv6).nh == 58):
                info = packet.summary()
                print('{:>8}  {:>8} {} {:<50}'.format(No, "ICMPv6",5*" ", info))

	elif ((packet.haslayer(TCP) or packet.haslayer(UDP)) and "Raw" in list(expand(packet)) and ((packet.load[4:8] == b'\xfeSMB') or (packet.load[0:4] == b'\xfeSMB'))): #SMB2
                info = packet.summary()
                print('{:>8}  {:>8} {} {:<50}'.format(No, "SMB2",5*" ", info))

	elif ((packet.haslayer(TCP) or packet.haslayer(UDP))  and "Raw" in list(expand(packet)) and ((packet.load[4:8] == b'\xffSMB') or (packet.load[0:4] == b'\xffSMB'))): #SMB
                info = packet.summary()
                print('{:>8}  {:>8} {} {:<50}'.format(No, "SMB",5*" ", info))

	elif ((packet.haslayer(UDP) and ("Raw" in list(expand(packet))) and b'ssdp:discover'  in packet.load)):
                info = packet.summary()
                print('{:>8}  {:>8} {} {:<50}'.format(No, "SSDP",5*" ", info))

	elif (packet.haslayer(HSRP)):
                info = packet.summary()
                print('{:>8}  {:>8} {} {:<50}'.format(No, "HSRP",5*" ", info))

	elif (packet.haslayer(UDP) and "Raw" in list(expand(packet))):
                info = packet.summary()
                print('{:>8}  {:>8} {} {:<50}'.format(No, "UDP",5*" ", info))
	elif (packet.haslayer(TCP) and not("Raw" in list(expand(packet)))):
                info = packet.summary()
                print('{:>8}  {:>8} {} {:<50}'.format(No, "TCP",5*" ", info))
	else:
                unknownInfo = packet.summary()
                if "0x8035" in unknownInfo:
                    protocolName = "RARP"
                    info = "rarp info"
                else:
                    protocolName = "###"
                    info = '{}{}'.format("#??#","&&&&")
                print('{:>8}  {:>8} {} {:<50}'.format(No, protocolName, 5*" ", info))
	i = i+1


i = 0
sniff(prn=lambda x: parsePacket(x))
