# coding:utf-8

from scapy.all import *

def ftpPcapReport(pcapName):
    filename = "reqpcap/" + pcapName
    logfile = open("ftp.log",'a')
    data = sniff(offline=filename)
    print "[+] Load pcap %s success!" % filename
    ftp_info = {}
    for i in range(0,len(data)):
        if data[i][TCP].dport == 21:
            try:
                ftp_pcap = data[i]
                ftp_info['src'] = ftp_pcap[IP].src
                ftp_info['dst'] = ftp_pcap[IP].dst
                if 'USER' in ftp_pcap[Raw].load:
                    ftp_user = ftp_pcap[Raw].load.split("\r\n")[0]
                    ftp_info['ftp_user'] = ftp_user
                if 'PASS' in ftp_pcap[Raw].load:
                    ftp_pass = ftp_pcap[Raw].load.split("\r\n")[0]
                    ftp_info['ftp_pass'] = ftp_pass
            except:
                pass
    if len(ftp_info) > 0:
        try:
            logfile.write("ftp_addr:"+ftp_info['dst']+'\n')
            logfile.write("ftp_user:"+ftp_info['ftp_user']+'\n')
            logfile.write("ftp_pass:"+ftp_info['ftp_pass']+'\n\n')
        except:
            pass
    logfile.close()
