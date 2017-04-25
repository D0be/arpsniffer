# coding:utf-8
import os
import sys


def start_info():

    print """           _        _____       _  __  __          
          (_)      / ____|     (_)/ _|/ _|         
 __      ___ _ __ | (___  _ __  _| |_| |_ ___ _ __ 
 \ \ /\ / / | '_ \ \___ \| '_ \| |  _|  _/ _ \ '__|
  \ V  V /| | | | |____) | | | | | | | ||  __/ |   
   \_/\_/ |_|_| |_|_____/|_| |_|_|_| |_| \___|_|   
                                                   
                                                   """
def tips_info():

    print """
--------------------------------
|    banner:V 1.0              |
--------------------------------
|    python:2.7.13             |
--------------------------------
|    Dos:Windows 10            |
--------------------------------
    """

def help_info():

    print """
[*]Setting parameters using "SET"
[*]Parameter:local-target-gateway
[*]Use "HELP" to view help information
    """


def input_parameter():

    parameter = []
    length = 0
    local_ip = None
    target_ip = None
    gateway = None

    while local_ip ==None or target_ip == None or gateway == None:
        data = raw_input("winSniffer >>")

        if data.startswith("SET") or data.startswith("set"):
            data = data.split(" ")
            if data[1] == 'local':
                local_ip = data[2]
            elif data[1] == 'target':
                target_ip = data[2]
            elif data[1] == 'gateway':
                gateway = data[2]
            else:
                print "[*] ERROR Input"

        elif data.startswith("cls") or data.startswith("CLS"):
            os.system("cls")

        elif data.startswith("exit") or data.startswith("EXIT"):
            sys.exit(0)

        elif data.startswith("help") or data.startswith("HELP"):
            help_info()
            
        else:
            print "[*] ERROR Input"

    parameter.append(local_ip)
    parameter.append(target_ip)
    parameter.append(gateway)
    
    return parameter
