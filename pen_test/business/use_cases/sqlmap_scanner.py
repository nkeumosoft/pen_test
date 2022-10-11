import logging
import os
import re
import shlex
import subprocess
import sys
from typing import List, Optional
from xml.etree import ElementTree as xml_tree


class SqlmapScannerError(Exception):
    """
    Exception error class for SqlmapScanner class

    """

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

    def __repr__(self):
        return f"SqlmapScannerError exception {self.value}"


first_space = sys.version.find(' ')


class SqlMapScanner:
    # def __init__(self, url):
        # self._url = url
    def __init__(
                self,
                sqlmap_search_path="sqlmap"):
            """
            Initialize SqlmapScanner module

            * detects sqlmap on the system and sqlmap version

            """
            self._sqlmap_path = sqlmap_search_path # sqlmap path
            self._scan_result = {}
            self._sqlmap_version_number = sys.version_info.major  # sqlmap version number
            self._sqlmap_subversion_number = sys.version_info.minor  # sqlmap subversion number
            self._sqlmap_last_output = None # last full ascii sqlmap output

            self.__process = None

    def scan(self, url="kali.tools/?p=816",  arguments=" ", level_of_output_msg: int = 4, timeout=0) -> str:
        # subprocess.run(["sqlmap", "-u", url, "-vvvvv --batch"])  # A enlever
        h_args = shlex.split(url)
        f_args = shlex.split(arguments)
        output_level = shlex.split(f"{level_of_output_msg} ")
        args = (
                [self._sqlmap_path, "-u", url, f"--batch"]

                + f_args
                + [f"-v {level_of_output_msg}"]

        )
        logging.error(args)
        logging.info("Waiting for sqlmap to finish to capture the result ...")
        result = subprocess.Popen(
            args,
            bufsize=100000,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        #
        caputure_stdin = result.communicate()
        # logging.error(caputure_stdin)

        if timeout == 0:
            caputure_stdin = result.communicate()
            self._sql_map_last_output, sql_map_err = caputure_stdin
        else:
            logging.warning("result.communicate()")
            logging.warning(result.communicate())
            try:
                (self._sql_map_last_output, sql_map_err) = result.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                result.kill()
                raise SqlmapScannerError("Timeout from sqlmap process")

        #caputure_stdin = bytes.decode(caputure_stdin[0])

        return self.analyse_sqlmap_scan(sqlmap_output=caputure_stdin[0])

    def analyse_sqlmap_scan(self, sqlmap_output: bytes = None,
                            sqlmap_err: str = "") -> Optional[str]:
        if sqlmap_output:
            self._sqlmap_last_output = bytes.decode(sqlmap_output)

        try:
            logging.error(self._sqlmap_last_output)
            return self._sqlmap_last_output
        except Exception:
            if len(sqlmap_err) > 0:
                raise SqlmapScannerError(sqlmap_err)
            else:
                raise SqlmapScannerError(self._sqlmap_last_output)

        return None


def sqlmap_launch_scan(url, arguments, level_of_output_msg=4, timeout=0):
    """
    Launch sqlmap scan

    :param url: url to scan
    :param arguments: sqlmap arguments
    :param level_of_output_msg: level of output message
    :param timeout: timeout for sqlmap process
    :return: sqlmap output
    """
    sqlmap_scanner = SqlMapScanner()
    return sqlmap_scanner.scan(url, arguments, level_of_output_msg, timeout)


if __name__ == "__main__":
    scanner = SqlMapScanner()
    result_of_scan = scanner.scan(url="http://testphp.vulnweb.com/artists.php?artist=1")
    print(f"test {result_of_scan}")


