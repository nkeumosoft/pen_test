import asyncio
import json
import logging
from typing import Dict

from nmap import PortScannerAsync, PortScanner
import csv
from pen_test.business.entity import NmapScanInfoEntity, NmapScanResultEntity
from pen_test.business.interfaces.inamp_scan import IScanPort
from pen_test.business.use_cases.nmap_scan_result import create_nmap_scan_result


class NmapScanPort(IScanPort):
    _host: str
    _port: str
    _arguments: str

    _nmap_scan: PortScanner

    def __init__(self, host: str, port: str, args:str, nmap_scan: PortScanner = PortScanner(), sudo: bool=True):
        self._host = host
        self._port = port
        self._nmap_scan = nmap_scan
        self._arguments = args
        self._result = None
        self.sudo = sudo

    @property
    def nmap_scan(self):
        return self._nmap_scan

    @property
    def arguments(self):
        return self._arguments

    @arguments.setter
    def arguments(self, arguments):
        self._arguments = arguments

    @property
    def result(self):
        return self._result

    @result.setter
    def result(self, scan_result):

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

    def all_hosts(self):
        if "scan" not in list(self.result.keys()):
            return []
        listh = list(self.result["scan"].keys())
        listh.sort()
        return listh

    async def scan(self):
        logging.warning(self.arguments)
        scan_result = self._nmap_scan.scan(
            hosts=self.host,
            ports=self.port,
            arguments=self.arguments,
            sudo=self.sudo
        )
        self.result = scan_result
        for key in self.result.keys():
            print('1234', key)
        # logging.warning(json.dumps(self.result, indent=5, sort_keys=True))
        logging.info("Done >>>")
        # return scan_result

    async def save_to_db(self) -> dict:
        """ is suppose to save in db but the data is too big to save """
        await asyncio.gather(self.scan())
        # result_in_csv_format = self._nmap_scan.csv()
        return self.result
        # result_of_scan = result_in_csv_format.replace('cpe\r\n', '')
        # result_of_scan = result_of_scan.replace('\r\n', '')
        # result_of_scan = result_of_scan.split(';')
        # result_of_scan = result_of_scan[11:]
        # # we remove the head
        #
        # protocol = result_of_scan[3] or None
        # port = result_of_scan[4] or None
        # name = result_of_scan[5] or None
        # state = result_of_scan[6] or None
        # product = result_of_scan[7] or None
        # extra_info = result_of_scan[8] or None
        # reason = result_of_scan[9] or None
        # version = result_of_scan[10] or None
        # conf = result_of_scan[11] or None
        # cpe = result_of_scan[12] or None
        # result = NmapScanResultEntity(
        #     scan_id=web.id,
        #     protocol=protocol,
        #     port=port,
        #     name=name,
        #     state=state,
        #     product=product,
        #     extra_info=extra_info,
        #     reason=reason,
        #     version=version,
        #     conf=conf,
        #     cpe=cpe,
        # )
        # create_nmap_scan_result(result)
