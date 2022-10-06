import asyncio
import json
import logging
import socket
from asyncio import as_completed
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional, Tuple

from infrastructure.framework import db
from infrastructure.framework.models import NmapScanInfo, Website
from infrastructure.repository.nmapscaninfo_repo import NmapScanInfoRepository
from infrastructure.repository.website_repository import WebsiteRepository
from pen_test.business.entity import NmapScanInfoEntity
from pen_test.business.use_cases.nmap_scan_port import NmapScanPort


def update_nmap_scan_info(nmap_scan_info_entity: NmapScanInfoEntity) -> NmapScanInfoEntity:
    """Update a nmap_scan_info."""

    nmap_scan_info = NmapScanInfoRepository(db, NmapScanInfo)

    return nmap_scan_info.update(nmap_scan_info_entity)


def create_nmap_scan_info(nmap_scan_info_entity: NmapScanInfoEntity) -> NmapScanInfoEntity:
    nmap_scan_info = NmapScanInfoRepository(db, NmapScanInfo)

    return nmap_scan_info.create(nmap_scan_info_entity)


def list_nmap_info() -> List[NmapScanInfoEntity]:
    """Update a nmap_scan_info."""

    nmap_scan_info = NmapScanInfoRepository(db, NmapScanInfo)

    return nmap_scan_info.list()


def nmap_scan(websites: List[NmapScanInfoEntity], threads=4) -> None:
    """Create a nmap scan result. with list of nmap scan info entity"""
    logging.error('Regular Scan')
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(scan_port_with_nmap, website): website
            for website in websites
        }
        exception = futures.exception()
        # handle exceptional case
        if exception:
            logging.error(exception)


def scan_port_with_nmap(website: Website, nmap_scan_info: NmapScanInfoEntity) -> Optional[dict]:
    """Scan port with nmap"""

    try:

        logging.warning(f'the second last  test to deploy {nmap_scan_info.website_id == website.id}')
        # website = website_repo.find(nmap_scan_info.website_id)
        logging.warning(f'the second last  test to deploy 2 {nmap_scan_info.website_id == website.id}')
        # logging.error(website)
        host_url = check_url_for_nmap(website.url)

        logging.error(host_url)

        port = nmap_scan_info.ports
        args = nmap_scan_info.arguments
        host_ip = socket.gethostbyname(host_url)
        logging.error(host_ip)
        nmap_scaner = NmapScanPort(host=host_ip, port=port, args=args)

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result: dict = loop.run_until_complete(nmap_scaner.save_to_db())
        loop.close()
        port_list: dict = {}
        if result and isinstance(result, dict):

            logging.warning(result.get('nmap').get('scaninfo'))
            total_scan = result.get('scan')
            scan = total_scan.get(host_ip)
            host_name = total_scan.get("hostnames")
            status = total_scan.get("status")
            vendor = total_scan.get("vendor")
            if scan:
                port_list = scan.get('tcp') or scan.get('udp')
            # 'command_line': 'nmap -oX - -p 80-88 127.0.0.1', 'scaninfo': {
            #     'tcp': {'method': 'syn', 'services': '80-88'}
            # },
            # 'scanstats': {
            #     'timestr': 'Tue Oct  4 12:38:57 2022', 'elapsed': '0.22', 'uphosts': '1', 'downhosts': '0',
            #     'totalhosts': '1'
            # }}
            context_result = {
                "hostnames": host_name or {},
                "vendor": vendor or {},
                "status": status or {},
                "port_found": port_list or {},
                "command_line": result.get("nmap").get("command_line") or {},
                "info_scan": result.get("nmap").get('scaninfo') or {},
                "stats": result.get("nmap").get('scanstats') or {},

            }
            logging.warning(json.dumps(context_result, indent=4, sort_keys=True))
            return context_result
        logging.error('Scan port with nmap')
    except socket.gaierror:
        logging.error('Name or service not known')
    except socket.error:
        logging.error('Could not connect to server')

    return None


def check_url_for_nmap(host_url: str) -> str:
    """
        an url must be like : www.name_of_url.domain_name or if it is a ip address
        an ip must be like : 127.0.0.1 without port parameter
        not like name_of_url.domain_name or 127.0.0.1:port
        params: host_url : str
        return host_url: str
    """

    host_url = check_http_or_https(host_url)
    ip_identification: tuple = ('1', '2', '4', '5', '6', '7', '8', '9', '0')
    logging.error(f"12345:  {host_url.find(':')}")

    if host_url.endswith('/') or host_url.find('/') >= 0:
        slash_indice = host_url.find('/')
        host_url = host_url[0: slash_indice]

    if host_url.find(':') >= 0:
        index = host_url.find(':')
        logging.error(host_url[0:index])
        host_url = host_url[0:index]
        logging.error('Scan port with nmap')

    if not host_url.startswith('www.') and not host_url.startswith(ip_identification):
        host_url = 'www.' + host_url

    return host_url


def check_http_or_https(host_url: str) -> str:
    """
            remove the http or https protocol of a head of url  if is present

            an url must be like : www.name_of_url.domain_name or if it is a ip address
            an ip must be like : 127.0.0.1 without port parameter

            and an url doesn't start with https:// or http:// protocol

            Param: host_url : str
            Return host_url: str
    """

    https_protocol: str = 'https://'
    http_protocol: str = 'http://'

    if https_protocol in host_url:
        return host_url.replace(https_protocol, '')
    elif http_protocol in host_url:
        return host_url.replace(http_protocol, '')
    return host_url


def nested_scan_result(nmap_scan_result: dict):
    """
            This function accepts a nested dictionary as argument
            and iterate over all values of nested dictionaries
        """

    # Iterate over all key-value pairs of dict argument
    for key, value in nmap_scan_result.items():
        # Check if value is of dict type
        if isinstance(value, dict):
            # If value is dict then iterate over all its values
            for sub_dict in nested_scan_result(value):
                yield key, *sub_dict
        else:
            # If value is not dict type then yield the value
            yield key, value
