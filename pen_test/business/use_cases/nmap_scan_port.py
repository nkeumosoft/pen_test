from typing import Dict

from nmap import PortScanner

from pen_test.business.interfaces.inamp_scan import IScanPort


class NmapScanPort(IScanPort):
    _host: str
    _port: str
    _result: Dict
    _nmap_scan: PortScanner

    def __init__(self, host: str, port: str, nmap_scan: PortScanner = PortScanner()):
        self._host = host
        self._port = port
        self._nmap_scan = nmap_scan
        self._result = {}

    @property
    def result(self):
        return self._result

    @result.setter
    def result(self, result: Dict):
        self._result = result

    @property
    def host(self) -> str:
        return self._host

    @property
    def port(self) -> str:
        return self._port

    def scan(self, host: str, ports: str = None) -> Dict:
        self.result = self._nmap_scan.scan(host, ports)
        return self.result
