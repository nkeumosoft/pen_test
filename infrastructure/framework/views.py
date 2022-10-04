import json
import logging
from typing import List
from uuid import UUID

from flask import redirect, request, url_for
from flask_admin import AdminIndexView, BaseView, expose
from flask_paginate import Pagination, get_page_parameter

from infrastructure.framework import db
from infrastructure.framework.forms import SearchForm, WebsiteForm
from infrastructure.framework.models import PenTestVulnerability, PentestAnomalies, Website
from infrastructure.repository.anomalies_repos import AnomaliesRepository
from infrastructure.repository.vulnerability_repos import VulnerabilityRepository
from infrastructure.repository.website_repository import WebsiteRepository
from pen_test.business.entity import NmapScanInfoEntity, WebsiteEntity
from pen_test.business.use_cases.crud_website import create_website
from pen_test.business.use_cases.nmap_scan_result import get_list_namp, list_nmap_result
from pen_test.business.use_cases.nmapscan_info import create_nmap_scan_info, nmap_scan, scan_port_with_nmap
from pen_test.business.use_cases.pentest_result import PenTestResult
from pen_test.business.use_cases.pentestresultdetail import launch_pentest, scan_list_website


class MyHomeView(AdminIndexView):
    @expose('/', methods=['GET'])
    def index(self):
        website_repo = WebsiteRepository(db, Website)
        list_of_website = website_repo.list()

        q = request.args.get('q')
        if q:
            search = True

        page = request.args.get(get_page_parameter(), type=int, default=1)

        len_list_website = len(list_of_website)

        pagination = Pagination(page=page, total=len_list_website, search=False, record_name='websites')

        return self.render('run_pentest.html', websites=list_of_website, pagination=pagination)

    @expose('/', methods=['POST'])
    def list_result(self):
        website_repo = WebsiteRepository(db, Website)
        list_of_website = website_repo.list()
        form = request.form.getlist('checked')
        if form:
            thread_number = 3
            logging.error(thread_number)
            logging.error(form)
            scan_list_website(form)

            return redirect(url_for('admin.index'))

        page = request.args.get(get_page_parameter(), type=int, default=1)

        len_list_website = len(list_of_website)

        pagination = Pagination(page=page, total=len_list_website, search=False, record_name='websites')

        return self.render(
            'run_pentest.html',
            websites=list_of_website,
            error_forms='please you must select at least 1 field',
            pagination=pagination)

    @expose('/result/<key>', methods=['GET'])
    def result(self, key):
        website_repo = WebsiteRepository(db, Website)
        website = website_repo.find(key)
        anomaly_repository = AnomaliesRepository(db, PentestAnomalies)
        vulnerability_repository = VulnerabilityRepository(db, PenTestVulnerability)
        launch_pentest(website.id)
        anomalies = anomaly_repository.filter_list_by_website(website.id)
        vulnerabilities = vulnerability_repository.filter_list_by_website(website.id)
        logging.error(anomalies)
        return self.render(
            'result_by_website.html',

            name="Vulnerabilities",
            vulnerabilities=vulnerabilities,
            anomalies=anomalies,
            name1="anomalies"
        )


class Home(BaseView):
    @expose('/', methods=['GET', 'POST'])
    def index(self):
        form = WebsiteForm()
        if form.validate_on_submit():
            website_repo = WebsiteRepository(db, Website)

            website_find = website_repo.find_by_url(form.data.get("url"))
            if not website_find:
                website_find = WebsiteEntity(url=form.data.get("url"), name=form.data.get("name"))

                create_website(website_find)

            return redirect(url_for('admin.index'))

            # vul_repo = VulnerabilityRepository(db, PenTestVulnerability)
            # anomaly_repo = AnomaliesRepository(db, PentestAnomalies)
            # pen_test = PentTestRun(website_repo, vul_repo, anomaly_repo, )
            # pen_test.run()

        return self.render('website.html', request=request, form=form)


class Vulnerabilities(BaseView):
    @expose('/')
    def index(self):
        form = SearchForm()
        vul_repo = VulnerabilityRepository(db=db, model=PenTestVulnerability)
        anomalies_repo = AnomaliesRepository(db=db, model=PentestAnomalies)

        pent_result = PenTestResult(
            _url='',
            _vul_repo=vul_repo,
            _anomaly_repo=anomalies_repo,
        )
        vulnerabilities = pent_result.list_vul()

        return self.render('vulnerabilities_result.html', form=form, name="Vulnerabilities",
                           vulnerabilitiy=vulnerabilities)

    @expose('/<key>')
    def details(self, key):
        if key:
            vul_repo = VulnerabilityRepository(db=db,
                                               model=PenTestVulnerability)
            anomalies_repo = AnomaliesRepository(db=db, model=PentestAnomalies)

            pent_result = PenTestResult(
                _url='',
                _vul_repo=vul_repo,
                _anomaly_repo=anomalies_repo,
            )
            vulnerabilities = pent_result.get_vul_by_uuid(key)

            return self.render('detail.html', request=request, name=vulnerabilities.attack_name,
                               vulnerabilities=vulnerabilities)

    @expose('/search_vul', methods=['POST'])
    def search_vul(self):
        form = SearchForm()
        vulnerabilities = []
        logging.error(form.validate_on_submit())
        if form.validate_on_submit():
            logging.error(f'okay {request}')
            vul_repo = VulnerabilityRepository(db=db, model=PenTestVulnerability)

            url = form.data.get("url")
            website_repo = WebsiteRepository(db, Website)

            if url:
                website = website_repo.find_by_url(url)

                if website:
                    vulnerabilities = vul_repo.filter_list_by_website(website.id)

        return self.render(
            'vulnerabilities_result.html',
            name="Vulnerabilities",
            form=form,
            Vulnerabilities=vulnerabilities
        )


class Anomalies(BaseView):

    @expose('/')
    def index(self):
        form = SearchForm()
        anomalies = []
        vul_repo = VulnerabilityRepository(db=db,
                                           model=PenTestVulnerability)
        anomalies_repo = AnomaliesRepository(db=db,
                                             model=PentestAnomalies)

        pent_result = PenTestResult(
            _url='',
            _vul_repo=vul_repo,
            _anomaly_repo=anomalies_repo,
        )
        anomalies = pent_result.list_anomaly()

        return self.render('anomalies_result.html', form=form, name="anomalies",
                           Anomalies=anomalies)

    @expose('/<key>')
    def details(self, key):
        if key:
            vul_repo = VulnerabilityRepository(db=db,
                                               model=PenTestVulnerability)
            anomalies_repo = AnomaliesRepository(db=db, model=PentestAnomalies)

            pent_result = PenTestResult(
                _url='',
                _vul_repo=vul_repo,
                _anomaly_repo=anomalies_repo,
            )
            anomalies_details = pent_result.get_anomaly_by_uuid(key)

            return self.render('detail.html', request=request, name=anomalies_details.name,
                               Anomalies=anomalies_details)

        return redirect('/')

    @expose('/search_anomalies', methods=['POST'])
    def search_anomalies(self):
        form = SearchForm()
        anomalies = []
        if form.validate_on_submit():
            logging.error(f'okay {request}')
            anomalies_repo = AnomaliesRepository(db=db, model=PentestAnomalies)
            url = form.data.get("url")
            website_repo = WebsiteRepository(db, Website)

            if url:
                website = website_repo.find_by_url(url)
                logging.error(website)
                if website:
                    anomalies = anomalies_repo.filter_list_by_website(website.id)
            logging.error(anomalies)
        logging.error(anomalies)
        return self.render('anomalies_result.html', form=form, name="Anomalies", Anomalies=anomalies)


class NmapScanView(BaseView):

    @expose('/', methods=['GET', 'POST'])
    def index(self):
        website_repo = WebsiteRepository(db, Website)
        form = request.form
        list_of_website = website_repo.list()
        ping_options = {
            "TCP": "tcp_ping",
            "ICMP": "icmp",
            "UDP Ping": "udp_ping",
            "ICMP And TCP": "icmp_tcp",
        }
        context = {
            'Fragment Packets': 'frag_pack',
            'Enable IPv6 scanning': 'ip6',
            'Regular Scan': 'reg_scan',
            'Enable OS detection': 'os_detect',
            'UDP Scan': 'udp_scan',
            'Spoof source address': 'spoof_source',
        }

        if request.method == "POST":
            logging.warning(form)
            website_checked = form.get('website_name')
            # logging.warning(website_checked)
            if website_checked:

                website_id = UUID(website_checked)
                website = website_repo.find(website_id)
                logging.error(website)
                if website:
                    test = [('website_name', ''), ('normalScan', 'yes'),
                            ('scan_type', 'connect'), ('ping_type', 'none'),
                            ('g_options', '-f')]
                    nmap_scan_infos: NmapScanInfoEntity
                    normal_scan = form.get('normalScan')
                    start_port = form.get('start_port')
                    end_port = form.get('end_port')
                    port = check_port(start_port, end_port)
                    if 'no' in normal_scan:
                        scan_type = form.get('scan_type')
                        ping_type = form.get('ping_type')
                        ping_type = get_ping_type(ping_type)

                        website_args = form.getlist('g_options')
                        scan_type = get_scan_type(scan_type)

                        general_options = get_general_options(website_args)
                        args = f'{scan_type}  {general_options}  {ping_type}'

                        logging.warning(port)
                        nmap_scan_infos = NmapScanInfoEntity(website_id=website.id, arguments=args, ports=port)
                        nmap_scan_infos = create_nmap_scan_info(nmap_scan_infos)
                        nmap_scan_infos = nmap_scan_infos

                    else:
                        args = get_scan_type("normal")

                        nmap_scan_infos = NmapScanInfoEntity(website_id=website.id, arguments=args, ports=port)
                        nmap_scan_infos = create_nmap_scan_info(nmap_scan_infos)

                    logging.warning(f'the last test to deploy {nmap_scan_infos}')
                    result_of_scan = scan_port_with_nmap(website, nmap_scan_infos)
                    if not result_of_scan:
                        result_of_scan = {}
                    logging.warning(json.dumps(result_of_scan, indent=4, sort_keys=True))
                    return self.render(
                        'nmap_scan.html',
                        form=form,
                        websites=list_of_website,
                        arguments=context,
                        ping_options=ping_options,
                        stats=result_of_scan.get("stats"),
                        cmd = result_of_scan.get("command_line"),
                        info_scan=result_of_scan.get("info_scan"),
                        port_found=result_of_scan.get("port_found"),
                        len_of_table=len(result_of_scan.get("port_found")),
                        host_name=result_of_scan.get("hostnames"),
                        status=result_of_scan.get("status"),
                        vendor=result_of_scan.get("vendor"))

        return self.render(
            'nmap_scan.html', form=form,
            websites=list_of_website,
            arguments=context,
            ping_options=ping_options)


def check_port(start_port=None, end_port=None) -> str:
    if start_port and end_port:
        return f"{start_port}-{end_port}"
    elif start_port:
        return f"{start_port}"
    elif end_port:
        return f"{end_port}"
    return "80-88"


def get_general_options(options_name: List[str]) -> str:
    result_name: str = ''
    general_options = {
        'frag_pack': '-f ',
        'ip6': '-6 ',
        'reg_scan': '-sV ',
        'os_detect': '-O -A ',
        'udp_scan': '-sU ',
        'spoof_source': "-S ",
    }

    for name in options_name:
        result_name +='' + general_options.get(name)

    return result_name


def get_scan_type(scan_name: str) -> str:
    list_of_scan = {
        "normal": " ",
        "connect": "-sT ",
        "syn": "-sS ",
        "null": "-sN ",
        "fin": "-sF ",
        "xmas": "-sX ",
        "ack": "-sA ",
        "init_scan": "-sY ",
        "window": "-sW ",
        "Maimon": "-sM ",
    }
    return list_of_scan.get(scan_name)


def get_ping_type(ping_name: str) -> str:
    ping_options = {
        "tcp_ping": "-sP ",
        "icmp": "-PE ",
        "udp_ping": "-PU ",
        "icmp_tcp": "-sF ",

    }
    return ping_options.get(ping_name)