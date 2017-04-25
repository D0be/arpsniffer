# coding:utf-8
import optparse
import threading
import Process
import asciiart
import injectdemo


if __name__ == "__main__":

    """显示程序信息"""

    asciiart.start_info()
    asciiart.tips_info()

    """初始化信息"""

    localip,targetip,gatewayip = asciiart.input_parameter()
    domain,times,jslink = injectdemo.confirm_inject()
    
    """实例化一个Process对象，进行嗅探"""
    winstart = Process.sniffer(localip, targetip, gatewayip,domain,times,jslink)

    winstart.start()
