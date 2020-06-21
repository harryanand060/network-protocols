import argparse
import re
import serial
import time


class SerialInterface():
    def __init__(self):
        self.parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        # self.parser.add_argument("--cmd", help="command", type=str, default=None)
        self.parser.add_argument("-port", help="Serial Port", type=str, default=None)
        self.args = self.parser.parse_args()

        self.serialClient = None
        self.isLogin = False
        self.serialClient = serial.Serial()
        # ser.port = "/dev/ttyUSB0"
        self.serialClient.port = self.args.port
        # ser.port = "/dev/ttyS2"
        self.serialClient.baudrate = 115201
        self.serialClient.bytesize = serial.EIGHTBITS  # number of bits per bytes
        self.serialClient.parity = serial.PARITY_NONE  # set parity check: no parity
        self.serialClient.stopbits = serial.STOPBITS_ONE  # number of stop bits
        # ser.timeout = None          #block read
        # self.serialClient.timeout = None  # non-block read
        # ser.timeout = 2              #timeout block read
        self.serialClient.writeTimeout = 2  # timeout for write
        self.connect()
        # self.cmd = 'ifconfig'

    def connect(self):
        try:
            self.serialClient.open()
            # serialClient = serial.serial_for_url("loop://")
        except Exception as exp:
            print("Not able to open PORT: {}".format(exp))
            print("PORT Open: {}".format(self.serialClient.is_open))
            serialClient = None
            return False
        print("connected to {}".format(self.serialClient.port))
        return True

    def execute(self, cmd):
        out_write = self.writeCommandSerial(cmd)
        print("out_write: {}".format(out_write))
        bufStr = self.readSerial(timeout=3.0)
        output = [item.rstrip() for item in bufStr.split('\n')][1:-1]
        output = '\n'.join(output)
        print("bufstr: {}".format(output))
        ip_list = re.findall('(inet\saddr:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', output)
        print ("IP List {}".format(ip_list))
        str, def_ip = ip_list[0].split(':')
        print(def_ip)
        print ("Actual IP {}".format(def_ip))
        self.disconnect()
        return def_ip

    def writeSerial(self, cmdStr, isDoNotFlush=False):
        print("Enter writeSerial")
        print("PORT Open: {}".format(self.serialClient.is_open))
        if self.serialClient is None or not self.serialClient.is_open:
            return None

        if cmdStr is None or len(cmdStr) <= 0:
            return None

        numBytesWritten = self.serialClient.write(self.s2b(cmdStr))
        print("Check isDoNotFlush {}".format(isDoNotFlush))
        if not isDoNotFlush:
            self.serialClient.flush()
        return numBytesWritten

    def readSerial(self, numBytes=1024, timeout=None):
        print("Enter readSerial")
        print("PORT Open: {}".format(self.serialClient.is_open))
        if self.serialClient is None or not self.serialClient.is_open:
            return None

        time.sleep(3)

        if timeout is not None:
            self.serialClient.timeout = timeout

        buf = self.serialClient.read(numBytes).decode('utf-8', 'ignore')
        strBuf = self.b2s(buf)

        self.serialClient.timeout = None
        return strBuf

    def b2s(self, buf):
        return str(buf)

    def s2b(self, textStr):
        print("String to byte")
        return bytes(textStr)

    def writeCommandSerial(self, cmdStr):
        if cmdStr is None:
            return None
        return self.writeSerial(str(cmdStr) + "\n")

    def disconnect(self):

        if not self.serialClient is None:
            if self.isLogin:
                self.writeCommandSerial("exit")
                print("logged out")

            # hang up
            self.serialClient.close()
            print("disconnected from remote")
            # print("PORT Open: {}".format(self.serialClient.is_open))
        return

if __name__ == '__main__':
    try:
        obj = SerialInterface()
        ip = obj.execute('ifconfig')
        print (ip)
    except EOFError:
        print("End of File Error")
    except Exception as e:
        print("Exception occurred {}".format(e))
