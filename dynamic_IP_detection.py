import re
import serial
import time


def get_ip(port):
    numBytes = 1024
    cmd = 'ifconfig'
    serialClient = serial.Serial()

    serialClient.port = port

    serialClient.baudrate = 115201
    serialClient.bytesize = serial.EIGHTBITS  # number of bits per bytes
    serialClient.parity = serial.PARITY_NONE  # set parity check: no parity
    serialClient.stopbits = serial.STOPBITS_ONE  # number of stop bits

    serialClient.writeTimeout = 2  # timeout for write
    serialClient.open()
    serialClient.timeout = 3.0
    textStr = cmd + "\n"
    out_write = serialClient.write(bytes(textStr))
    print("out_write: {}".format(out_write))
    time.sleep(3)
    bufStr = serialClient.read(numBytes).decode('utf-8', 'ignore')
    output = [item.rstrip() for item in bufStr.split('\n')][1:-1]
    output = '\n'.join(output)
    print("bufstr: {}".format(output))
    ip_list = re.findall('(inet\saddr:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', output)
    print ("IP List {}".format(ip_list))
    str, def_ip = ip_list[0].split(':')
    print(def_ip)
    print ("Actual IP {}".format(def_ip))
    serialClient.close()
    print("disconnected from remote")
    return def_ip
