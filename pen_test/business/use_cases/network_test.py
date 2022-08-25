import nmap3

from pen_test.business.interfaces.ipen_test import IPentTest


class NmapTest(IPentTest):

    def nmap_port(self):
        nmap = nmap3.Nmap()
        nmap.scan_top_ports(self.url)

    def nmap_brute_force_dns(self):
        nmap = nmap3.Nmap()
        nmap.nmap_dns_brute_script(self.url)

    def execute(self):
        ...
