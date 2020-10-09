#!/usr/bin/env python3

import os
import subprocess
from telnetlib import Telnet 
import time


class TelnetConnection():
    """
    ** Telnet interface  **

    """

    def __init__(self, **kwargs):
        print('Initialize telnet interface')
        self.telnet_con = None
        try:
            self.ip = kwargs.get('ip')
            self.port = kwargs.get('port')
            self.user_name = kwargs.get('user', 'root')
        except Exception as e:
            raise Exception('Interface Initialization failed: [ %s ]' % str(e))

    def connect(self, **kwargs):
        """
        Connect using telnet library of python

        :return: None
        """
        print("telnet Connection with ip {} and port {}".format(self.ip, self.port))
        self.telnet_con = Telnet(self.ip, self.port)

    def execute(self, input: str, timeout: int = 5, working_directory: str = None) -> str:
        """
        Execute function of telnet Interface
        input the command and return command output

        :param input: Command to Execute
        :param timeout: Wait time for command execution
        :param working_directory: If Passed, cd to this directory to perform execution
        :return: str
        """
        try:
            if working_directory:
                # Store Present Directory
                self.telnet_con.write('pwd'.encode('ascii') + b'\n')
                # Need to wait a little for output
                time.sleep(1)
                try:
                    present_working_directory = self.loc_read_very_eager().decode('ascii', 'ignore'). \
                                                    rstrip('r').split('\n')[1:-1][0]
                except IndexError as e:
                    raise Exception(f"PWD output is empty, exception {e}")

                # Change to Working Directory
                self.telnet_con.write('cd {}'.format(working_directory).encode('ascii') + b'\n')
                time.sleep(1)
                # Clear the buffer by doing read_very_eager operation
                self.loc_read_very_eager().decode('ascii', 'ignore')

            print("Telnet Execute with input as {} ".format(input))
            self.telnet_con.write(input.encode('ascii') + b'\n')
            time.sleep(timeout)
            # Store the output so that buffer is not loaded with unwanted Data
            output = self.loc_read_very_eager().decode('ascii', 'ignore').rstrip('r').split('\n')[1:-1]
            if working_directory:
                # Change Back to the Directory previously stored
                self.telnet_con.write(f'cd {present_working_directory}'.encode('ascii') + b'\n')
            return "\n".join(output)
        except Exception as e:
            raise Exception("Telnet Command Execution exception") from e

    def loc_expect(self, output: any) -> object:
        """
        Wrapper Function for telnet interface. This uses underlying python telnet libraries
        Read until one from a list of a regular expressions matches.

        :param output: Command to execute
        :return: None
        """
        print("Telnet expect with {}".format(output))
        (i, obj, res) = self.telnet_con.expect([output.encode('ascii')], 5)
        print("i inside is {} ".format(i))
        return i

    def loc_read_very_eager(self) -> bytes:
        """
        Read everything that can be without blocking in I/O (eager).

        :return: String
        """
        print("Telnet Read Very eager")
        out = self.telnet_con.read_very_eager()
        return out

    def loc_write(self, cmd: str) -> None:
        """
        Write a string to the socket.

        :param cmd:
        :return: None
        """
        print("Telnet write")
        self.telnet_con.write(cmd.encode('ascii') + b'\n')

    def close(self) -> None:
        """
        Close the connection.

        :return: None
        """
        print('Telnet Close')
        if self.telnet_con:
            self.telnet_con.close()

    def stop_command_execution(self, default_dir: str = "home/root", **kwargs) -> None:
        """
        Stop Ongoing execution by sending Interrupt

        :return: None
        """
        send_control_c = '\x03'

        hash_prompt = kwargs.get('hash_prompt', '~#')

        # Making Sure we stop the Execution
        for i in range(2):
            self.telnet_con.write(send_control_c.encode('ascii') + b'\n')

        out = self.telnet_con.read_until(hash_prompt.encode('ascii'), 2)
        if hash_prompt not in str(out):
            raise Exception("Could not stop the Execution, Session seems to be hung")

        self.telnet_con.write('cd {}'.format(default_dir).encode('ascii') + b'\n')

    def copy_file_to_or_from_target(self, src_path: str, dst_path: str, to_target: bool = True, ) -> bool:
        """
        Copy files either to target or from target based on the to_target flag value

        :param src_path: Path from which item have to to be copied
        :param dst_path: Path to which item have to be copied
        :param to_target: Flag to indicate the direction
        :return:Boolean

        """
        # TODO: Identify the type of test interface if IP does not exist

        print(f'Coping file src: {src_path} to dst: {dst_path} - to_target: {to_target}')
        try:
            if to_target:
                print("copy from host to target")
                if os.path.exists(src_path):
                    cmd = f"scp -q -r -o {src_path} {self.user_name}@{self.ip}:{dst_path}"
                else:
                    print("Source path not found, returning")
                    return False
            else:
                print("Copy From target to HOST")
                cmd = f"scp -q -r -o {self.user_name}@{self.ip}:{src_path} {dst_path}"

            out, err = self.execute_process(cmd, True)
            if err:
                print("Error in copying files from Host to target")
                return False

        except Exception as e:
            Exception("Exception of Copy files to/From Target {}".format(e))
            return False

        return True

    def execute_process(cmd: str, capture_output: bool = False, display_output: bool = True, timeout: int = 5) -> tuple:
        """
        Execute Command and wait for the process completion, also capture output based on flag

        :param cmd: Command To execute
        :param capture_output: Whether to capture output or not
        :param timeout: Max Timeout
        :param display_output: If set to False, will not display the output over console. Default to True.
        :param timeout: command timeout in case of command to be executed remotely using platform_obj.execute().
        Default to 5 secs
        :return: tuple
        """
        try:

            if capture_output:
                print("Execute with capturing output")
                p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                out, err = p.communicate()

                if display_output:
                    if out:
                        print(f"Output is: \n{'*' * 10} Output Start {'*' * 10}\n'"
                              f"{out.decode('utf-8', 'ignore')}'\n{'*' * 10} Output End {'*' * 10}\n")
                    if err:
                        print(f"Error is: \n{'*' * 10} Error Start {'*' * 10}\n'"
                              f"{err.decode('utf-8', 'ignore')}'\n{'*' * 10} Error End {'*' * 10}\n")
                return out, err
            else:
                p = subprocess.Popen(cmd, shell=True)
                p.communicate()

        except Exception as exp:
            raise Exception(' %s Process failed: %s' % (cmd, str(exp)))
