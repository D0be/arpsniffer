# coding:utf-8

from scapy.all import *

def httpPcapReport(pcapName):

    http_headers = []
    filename = "reqpcap/"+pcapName
    logfile = open("result.log","a")
    cookiefile = open("cookie.log","a")
    data = sniff(offline=filename)
    print "[+] Load pcap %s success!" % filename
    report = open("reqpcap/"+pcapName+".html","w")

    for i in range(0,len(data)):
        if 'HTTP' in str(data[i].payload.payload.payload):
            header = str(data[i].payload.payload.payload)
            http_headers.append(header)
            cookie = data[i].payload.payload.payload.load.split("\r\n")
            for i in cookie:
                if ("Cookie" in str(cookie)) and ("Host" or "Referer"  in str(cookie)):
                    if "Referer" in i:
                        cookiefile.write(i)
                    if "Host" in i:
                        cookiefile.write(i)
                    if "Cookie" in i:
                        cookiefile.write(i)
                    if 'Set-Cookie' in i:
                        cookiefile.write(i)
                    cookiefile.write("\n")
            if 'POST' or 'GET' in header:
                if ('user' or 'pass') in header:
                    logfile.write("[*] "+filename+":may be sensitive information in the pcap\nNumbering:"+str(i))

    for i in http_headers:
        i = i.split("\r\n")
        report.write("<p>")
        for con in i:
			report.write(con+"<br>")
        report.write("</p><br>")
    report.close()
    cookiefile.close()
    logfile.close()
    print "[-] %s report over!" % filename


def httpPcapRep(pcapName):
    http_headers = []
    filename = "reppcap/"+pcapName
    logfile = open("result.log","a")
    cookiefile = open("cookie.log","a")
    data = sniff(offline=filename)
    print "[*] Load pcap %s success!" % filename
    report = open("reppcap/"+pcapName+".html","w")

    for i in range(0,len(data)):
        if 'HTTP' in str(data[i].payload.payload.payload):
            header = str(data[i].payload.payload.payload)
            http_headers.append(header)
            cookie = data[i].payload.payload.payload.load.split("\r\n")
            for i in cookie:
                if ("Cookie" or "Set-Cookie" in str(cookie)) and ("Host" or "Referer" in str(cookie)):
                    if "Referer" in i:
                        cookiefile.write(i)
                    if "Host" in i:
                        cookiefile.write(i)
                    if "Cookie" in i:
                        cookiefile.write(i)
                    if 'Set-Cookie' in i:
                        cookiefile.write(i)
                    cookiefile.write("\n")
            if 'POST' or 'GET' in header:
                if ('user' or 'pass' or 'pwd') in header:
                    logfile.write("[*] "+filename+":may be sensitive information in the pcap\nNumbering:"+str(i))

    for i in http_headers:
        i = i.split("\r\n")
        report.write("<p>")
        for con in i:
            report.write(con+"<br>")
        report.write("</p><br>")
    cookiefile.close()
    logfile.close()
    report.close()
    print "[-] %s report over!" % filename
