import platform
import os
import time
import socket
from backend_packet_sniffer import *


sniffer = Packet_Sniffer()


def start_up():
    clear_terminal()
    print("""Welcome to a CLI Pythonic packet sniffing and enumeration tool! 
This tool will be able to perform packet sniffing specific tasks
involving TCP/UDP packets and RAW data. It should be noted,
that while these activities have legal implications. Following Virginia and federal law,
capturing non-content, especially if the source is anonymized is perfectly legal,
for educational purposes. And any frowned upon actions will be tested against my local machine.
Source: http://conferences.sigcomm.org/imc/2007/papers/imc152.pdf""")
    user_input = input("""
Enter nothing to exit or any key to continue!
>>> """)
    user_input = user_input.replace(" ", "")
    user_input = user_input[:1]
    if user_input == "":
        print("""
Exiting...""")
        time.sleep(2)
        clear_terminal()
        exit()
    else:
        clear_terminal()
        start = True
        while start == True:
            print("Will you like to sniff for [R]AW data, [U]DP, or [T]CP packets?")
            user_input = input("""
>>> """)
            user_input = user_input.replace(" ", "")
            user_input = user_input[:1]
            user_input = user_input.lower()
            if user_input == "r":
                print("""
You have chosen RAW data.""")
                time.sleep(2)
                clear_terminal()
                try:
                    while True:
                         sniffer._raw_data()
                except KeyboardInterrupt:
                    start = False
            elif user_input == "u":
                print("""
You have chosen UDP packets.""")
                time.sleep(2)
                clear_terminal()
                try:
                    while True:
                        sniffer._local_udp()
                except KeyboardInterrupt:
                    start = False
            elif user_input == "t":
                print("""
You have chosen TCP packets.""")
                time.sleep(2)
                clear_terminal()
                try:
                    while True:
                        sniffer._local_tcp()
                except KeyboardInterrupt:
                    start = False
            else:
                print("Please choose a valid option!")
                time.sleep(2)
                clear_terminal()
                continue
        clear_terminal()
        exit()

def clear_terminal():
   # Check the operating system and clear the terminal accordingly
    if platform.system() == "Windows":
        os.system("cls")
    elif platform.system() == "Linux" or platform.system() == "Darwin": # For MacOS and Linux
        os.system("clear")
    else:
        print("\n" * 100) #For unindentified systems to get 100 new lines of code in terminal.


if __name__ == "__main__":
    start_up()