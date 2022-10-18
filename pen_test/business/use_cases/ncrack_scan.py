import logging
import os
import re
import shlex
import socket
import subprocess
import sys
from typing import List, Optional
from xml.etree import ElementTree as xml_tree

import xmltodict


class NcrackScannerError(Exception):
    """
    Exception error class for SqlmapScanner class

    """

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

    def __repr__(self):
        return f"NcrackScannerError exception {self.value}"


first_space = sys.version.find(' ')


class NcrackScanner:
    # def __init__(self, url):
        # self._url = url
    def __init__(
                self,
                ncrack_search_path=(
                        "ncrack",
                        "/bin/ncrack",
                                    )):
            """
            Initialize SqlmapScanner module

            * detects ncrack on the system and ncrack version

            """
            self._ncrack_path = ncrack_search_path # ncrack path
            self._scan_result = {}
            self._ncrack_version_number = 0  # ncrack version number
            self._ncrack_subversion_number = 0  # ncrack subversion number
            self._ncrack_last_output = "" # last full ascii ncrack output
            self.is_nmap_found = False
            self.__process = None
            self.ncrack_regex = re.compile(r"Ncrack version [0-9]*\.[0-9]*[^ ]* \( http(|s)://.* \)")
            self.get_ncrack_path(ncrack_search_path)

    def get_ncrack_path(self, ncrack_search_path: tuple[str]):

        for ncrack_path in ncrack_search_path:
            try:
                if (
                    sys.platform.startswith("freebsd")
                    or sys.platform.startswith("linux")
                    or sys.platform.startswith("darwin")
                ):
                    process_ouptut = subprocess.Popen(
                        [ncrack_path, "-V"],
                        bufsize=10000,
                        stdout=subprocess.PIPE,
                        close_fds=True,
                    )

                else:
                    process_ouptut = subprocess.Popen(
                        [ncrack_path, "-V"], bufsize=10000, stdout=subprocess.PIPE
                    )

            except OSError:
                pass
            else:
                self._ncrack_path = ncrack_path  # save path
                break
        else:
            raise NcrackScannerError(
                f" ncrack program was not found in path. PATH is : {os.getenv('PATH')}"
            )

        self.get_ncrack_version(process_ouptut)

        if not self.is_nmap_found:
            raise NcrackScannerError(
                f" ncrack program was not found in path.")

        return

    def get_ncrack_version(self, process_ouptut):

        self.ncrack_last_output = bytes.decode(process_ouptut.communicate()[0])

        for line in self.ncrack_last_output.split(os.linesep):

            if self.ncrack_regex.match(line) is not None:
                self.is_nmap_found = True
                # Search for version number
                regex_version = re.compile("[0-9]+")
                regex_subversion = re.compile(r"\.[0-9]+")

                rv = regex_version.search(line)
                rsv = regex_subversion.search(line)

                if rv is not None and rsv is not None:
                    # extract version/subversion
                    self._nmap_version_number = int(line[rv.start() : rv.end()])
                    self._nmap_subversion_number = int(
                        line[rsv.start() + 1 : rsv.end()]
                    )
                break

    def ncrack_version(self):
        """
                returns ncrack version if detected (int version, int subversion)
                or (0, 0) if unknown
                :returns: (_ncrack_version_number, _ncrack_version_number)
                """
        return self._ncrack_version_number, self._ncrack_version_number

    def file_scan(
            self, url="",
            path_username: str = "",
            path_password: str = "",
            pass_args: str = "",
            user_args: str = "",
            timeout=0
    ) -> tuple:
        if path_password == "" and path_username == "":
            return "Please provide a file to a username and password file"
        else:
            h_args = shlex.split(url)
            # user_args = "-U" if user_args == "" else user_args
            # pass_args = "-P" if pass_args == "" else pass_args
            logging.error('test')
            logging.error(path_password)
            logging.error(path_username)

            args = (
                    [self._ncrack_path, "-T5", "-vvvvv"]
                    + [user_args, path_username]
                    + [pass_args, path_password]
                    + h_args
        )

        logging.error(args)
        logging.info("Waiting for ncrack to finish to capture the result ...")
        result = subprocess.Popen(
            args,
            bufsize=100000,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        logging.warning("caputure_stdin")
        if timeout == 0:
            logging.warning("caputure_stdin")
            caputure_stdin = result.communicate()
            self._ncrack_last_output, ncrack_error = caputure_stdin
        else:
            logging.warning("result.communicate()")
            logging.warning(result.communicate())
            try:
                (self._ncrack_last_output, ncrack_error) = result.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                result.kill()
                raise NcrackScannerError("Timeout from ncrack process")
        ncrack_error = bytes.decode(ncrack_error)
        logging.warning((self._ncrack_last_output, ncrack_error))

        return self.analyse_ncrack_scan(ncrack_output=self._ncrack_last_output, ncrack_err=ncrack_error)

    def simple_scan(self, url="kali.tools/?p=816",  arguments=" ",  timeout=0) -> str:
        # subprocess.run(["ncrack", "-u", url, "-vvvvv --batch"])  # A enlever
        h_args = shlex.split(url)
        f_args = shlex.split(arguments)
        # output_level = shlex.split(f"{level_of_output_msg} ")
        # -oN/-oX <file>: Output scan in normal and XML format, respectively, to the given filename.
        #   -oA <basename>: Output in the two major formats at once
        args = (
                [self._ncrack_path, "-T5"]
                + h_args
                + f_args
                + ["-vvvvv"]

        )
        logging.error(args)
        logging.info("Waiting for ncrack to finish to capture the result ...")
        result = subprocess.Popen(
            args,
            bufsize=100000,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        #
        caputure_stdin = result.communicate()
        logging.warning(caputure_stdin)
        if timeout == 0:
            logging.warning("caputure_stdin")
            caputure_stdin = result.communicate()
            self._ncrack_last_output, ncrack_error = caputure_stdin
        else:
            logging.warning("result.communicate()")
            logging.warning(result.communicate())
            try:
                (self._ncrack_last_output, ncrack_error) = result.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                result.kill()
                raise NcrackScannerError("Timeout from ncrack process")

        return self.analyse_ncrack_scan(ncrack_output=self._ncrack_last_output)

    def analyse_ncrack_scan(self, ncrack_output: bytes = None,
                            ncrack_err: str = "") -> tuple:

        if ncrack_output:
            self.ncrack_last_output = bytes.decode(ncrack_output)

        try:
            dom = (self.ncrack_last_output, ncrack_err)

        except Exception:
            if len(ncrack_err) > 0:
                raise NcrackScannerError(ncrack_err)
            else:
                raise NcrackScannerError(self.ncrack_last_output)

        return dom


def ncrack_launch_scan(url, path_username, path_password, pass_args="", user_args="") -> tuple:
    """
     Launch ncrack scan with brute force
    :param url: url to scan
    :param arguments: sqlmap arguments
    :param timeout: timeout for sqlmap process
    :return: sqlmap output
    """
    try:

        host_ip = url
        ncrack_scanner = NcrackScanner()

        return ncrack_scanner.file_scan(host_ip, path_username, path_password, pass_args, user_args)

    except socket.gaierror:
        logging.error('Name or service not known')
    except socket.error:
        logging.error('Could not connect to server')

    return None


if __name__ == "__main__":

    print(
        ncrack_launch_scan("scanme.nmap.org 192.168.0.0/8 10.0.0,1,3-7.- -p22", "libert", 'dcnkk', "--pass", "--user"))
