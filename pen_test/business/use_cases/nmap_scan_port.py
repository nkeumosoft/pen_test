import json
import logging
from typing import Dict

from nmap import PortScanner,PortScannerAsync, PortScannerYield

from pen_test.business.interfaces.inamp_scan import IScanPort


class NmapScanPort(IScanPort):
    _host: str
    _port: str
    _result: Dict
    _nmap_scan: PortScannerAsync

    def __init__(self, host: str, port: str, nmap_scan: PortScannerAsync = PortScannerAsync()):
        self._host = host
        self._port = port
        self._nmap_scan = nmap_scan
        self._result = {}

    @property
    def result(self):
        return self._result

    @result.setter
    def result(self, scan_result):
        logging.error(scan_result)
        self._result = scan_result

    @property
    def host(self) -> str:
        return self._host

    @property
    def port(self) -> str:
        return self._port

    def scan_result(self, host, scan_result):
        logging.warning(f" de host:{host}\n result: {scan_result}")



        self._result = scan_result

    def scan(self, host: str, ports: str = None) -> Dict:
        self.result = self._nmap_scan.scan(host, ports)
        return self.result

    def async_scan(self):
        scan_result = self._nmap_scan.scan(
            hosts=self.host,
            ports=self.port,
            arguments='-sV',
            callback=self.scan_result)
        while self._nmap_scan.still_scanning():
            logging.info("Waiting >>>")
            self._nmap_scan.wait(2)

        nm = PortScannerYield()
        for progressive_result in nm.scan(self.host, self.port):
            logging.warning(progressive_result)
