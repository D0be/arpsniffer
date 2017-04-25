# coding:utf-8

from scapy.all import *

"""对数据包进行telnet数据分析，如果目的端口是23说明使用telnet协议

此时就将用户名和密码按照规则提取出来，之后存到telnet.log文件中"""


def telnetPcapReport(pcapName):
    filename = "reqpcap/" + pcapName
    logfile = open("telnet.log",'a')
    data = sniff(offline=filename)

    print "[+] Load pcap %s success!" % filename
    telnet_stream = ""
    telnet_info = {}

    for i in range(0,len(data)):
        if data[i][TCP].dport == 23:
            try:
                telnet_stream += data[i][Raw].load.decode('utf8')
                telnet_info['dst'] = data[i][IP].dst
            except:
                pass
    telnet_user = telnet_stream.split("\r\n")

    if len(telnet_user) >= 2:
        telnet_info['username'] = telnet_user[0]
        telnet_info['password'] = telnet_user[1]
        logfile.write("telnet-ip:"+telnet_info['dst']+'\n')
        logfile.write("username:"+telnet_info['username']+'\n')
        logfile.write("password:"+telnet_info['password']+"\n\n")
        
    logfile.close()