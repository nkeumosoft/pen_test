import json
import logging
import os
import uuid
from typing import List
from uuid import UUID

from flask import redirect, request, url_for
from flask_admin import AdminIndexView, BaseView, expose
from flask_paginate import Pagination, get_page_parameter

from infrastructure.framework import db
from infrastructure.framework.config import BaseConfig
from infrastructure.framework.forms import SearchForm, WebsiteForm
from infrastructure.framework.models import PenTestVulnerability, PentestAnomalies, Website
from infrastructure.repository.anomalies_repos import AnomaliesRepository
from infrastructure.repository.vulnerability_repos import VulnerabilityRepository
from infrastructure.repository.website_repository import WebsiteRepository
from pen_test.business.entity import NmapScanInfoEntity, WebsiteEntity
from pen_test.business.use_cases.crud_website import create_website
from pen_test.business.use_cases.ncrack_scan import ncrack_launch_scan
from pen_test.business.use_cases.nmapscan_info import create_nmap_scan_info, scan_port_with_nmap
from pen_test.business.use_cases.pentest_result import PenTestResult
from pen_test.business.use_cases.pentestresultdetail import launch_pentest, scan_list_website
from pen_test.business.use_cases.sqlmap_scanner import sqlmap_launch_scan


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
                           vulnerabilities=vulnerabilities)

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
            "no_ping": "none",
            "TCP": "tcp_ping",
            "ICMP": "icmp",
            "UDP Ping": "udp_ping",
            "ICMP And TCP": "icmp_tcp",
        }
        context = {
            'Fragment Packets': 'frag_pack',
            'Regular Scan': 'reg_scan',
            'Enable OS detection': 'os_detect',

        }
        form_error: str = None
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
                    logging.warning(normal_scan)
                    if 'no' in normal_scan:
                        scan_type = form.get('scan_type')
                        ping_type = form.get('ping_type')
                        logging.warning(ping_type)
                        ping_type = get_ping_type(ping_type)

                        website_args = form.getlist('g_options')
                        scan_type = get_scan_type(scan_type)

                        general_options = get_general_options(website_args)
                        args = f'{scan_type} 3  {general_options} 1 {ping_type}'

                        logging.warning(args)
                        nmap_scan_infos = NmapScanInfoEntity(website_id=website.id, arguments=args, ports=port)
                        nmap_scan_infos = create_nmap_scan_info(nmap_scan_infos)
                        nmap_scan_infos = nmap_scan_infos
                        logging.warning(f'the last test to deploy {nmap_scan_infos}')
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
                        cmd=result_of_scan.get("command_line"),
                        info_scan=result_of_scan.get("info_scan"),
                        port_found=result_of_scan.get("port_found"),
                        len_of_table=len(result_of_scan.get("port_found")),
                        host_name=result_of_scan.get("hostnames"),
                        status=result_of_scan.get("status"),
                        vendor=result_of_scan.get("vendor"))

            form_error = "Please choise your website"
        return self.render(
            'nmap_scan.html', form=form,
            websites=list_of_website,
            arguments=context,
            ping_options=ping_options,
            error_forms=form_error)


class SqlMapScanView(BaseView):

    @expose('/', methods=['GET', 'POST'])
    def index(self):

        website_repo = WebsiteRepository(db, Website)
        form = request.form
        list_of_website = website_repo.list()
        key_options = ["Optimizations", "Injection", "Fingerprint",
                       "Enumeration", "Brute force", "Windows registry access"]
        advance_options = \
            [
                {
                    "Optimizations":
                        {
                            "-o": "Turn on all optimization switches",
                            "--predict-output": "Predict common queries output",
                            "--keep-alive": "Use persistent HTTP(s) connections",
                            "--null-connection ": "Retrieve page length without actual HTTP response body"
                        },
                    'description': "These options can be used to optimize the performance"
                },
                {
                    'description': "These options can be used to specify which parameters to test for, provide custom "
                                   "injection payloads and optional tampering scripts",
                    "Injection":
                        {
                            " --skip-static": "Skip testing parameters that not appear to be dynamic",
                            "--invalid-bignum": "Use big numbers for invalidating values",
                            "--invalid-logical": "Use logical operations for invalidating values",
                            "--invalid-string": "Use random strings for invalidating values",
                            "--no-cast": "Turn off payload casting mechanism",
                            "--no-escape": "Turn off string escaping mechanism",
                        }
                },
                {
                    'description': "",
                    "Fingerprint":
                        {
                            "--fingerprint": "   Perform an extensive DBMS version fingerprint",

                        }
                },
                #   Detection:
                #     These options can be used to customize the detection phase
                #
                #     --level=LEVEL       Level of tests to perform (1-5, default 1)
                #     --risk=RISK         Risk of tests to perform (1-3, default 1)

                {
                    'description': "These options can be used to enumerate the back-end database"
                                   "management system information, structure and data contained in the  tables",
                    "Enumeration":
                        {
                            "--fingerprint": "   Perform an extensive DBMS version fingerprint",
                            "--all ": "Retrieve everything",
                            "--banner": " Retrieve DBMS banner",
                            "--current-user": "Retrieve DBMS current user",
                            "--current-db": "Retrieve DBMS current database",
                            "--hostname ": "Retrieve DBMS server hostname",
                            "--is-dba ": " Detect if the DBMS current user is DBA",
                            "--users ": " Enumerate DBMS users",
                            "--passwords": "Enumerate DBMS users password hashes",
                            "--privileges": "Enumerate DBMS users privileges",
                            "--roles  ": "Enumerate DBMS users roles",
                            "--dbs  ": "Enumerate DBMS databases",
                            "--tables": "Enumerate DBMS database tables",
                            "--columns": "Enumerate DBMS database table columns",
                            "--schema  ": " Enumerate DBMS schema",
                            "--count    ": "Retrieve number of entries for table(s)",
                            "--dump      ": "Dump DBMS database table entries",
                            "--dump-all   ": "Dump all DBMS databases tables entries",
                            "--search      ": "Search column(s), table(s) and/or database name(s)",
                            "--comments   ": "      Check for DBMS comments during enumeration",
                            "--statements  ": "Retrieve SQL statements being run on DBMS",

                        }
                },
                #   :
                #     
                #
                #    
                {
                    "description": "  These options can be used to run brute force checks",
                    "Brute force": {
                        "--common-tables": " Check existence of common tables",
                        "--common-columns": "Check existence of common columns",
                        "--common-files": " Check existence of common files"
                    },
                },
                {
                    "description": "These options can be used to access the back-end database management "
                                   "system Windows registry",
                    "Windows registry access": {
                        " --reg-read": "Read a Windows registry key value",
                        "--reg-add": "Write a Windows registry key value data",
                        " --reg-del ": "  Delete a Windows registry key value"
                    }
                }
            ]

        form_error = None
        if request.method == "POST":
            logging.warning(form)
            website_checked = form.get('website_name')
            # logging.warning(website_checked)
            if website_checked:

                website_id = UUID(website_checked)
                website = website_repo.find(website_id)
                logging.error(website)
                args: str = ""
                if website:
                    for key in key_options:
                        forms_args = form.get(key) or ""
                        args += f" {forms_args}"

                    logging.warning(args)
                    result_of_scan = sqlmap_launch_scan(website.url, args)
                    len_of_result = len(result_of_scan)
                    csv_file_location = "you can find results of scanning in multiple targets mode inside the CSV file"
                    if csv_file_location in result_of_scan:
                        csv_str = result_of_scan.find(csv_file_location)
                        result_of_scan = result_of_scan[:csv_str]
                    if not result_of_scan:
                        result_of_scan = "No result  \n"
                    val = result_of_scan.split("\n")

                    logging.warning(json.dumps(result_of_scan, indent=4, sort_keys=True))
                    return self.render(
                        'sqlmap_scan.html', form=form,
                        websites=list_of_website,
                        cmd=f"{website.url}  {args}",
                        advance_options=advance_options,
                        result_of_scan=result_of_scan.split("\n"),
                        error_forms=form_error or None)
            else:
                form_error = "Please choise your website"

        return self.render(
            'sqlmap_scan.html', form=form,
            websites=list_of_website,
            advance_options=advance_options,
            error_forms=form_error or None)


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
        'reg_scan': '-sV ',
        'os_detect': '-O -A ',

    }

    for name in options_name:
        result_name += '' + general_options.get(name)

    return result_name


def get_scan_type(scan_name: str) -> str:
    list_of_scan = {
        "normal": " ",
        "connect": "-sT ",
        "syn": "-sS",
        "null": "-sN ",
        "fin": "-sF ",
        "xmas": "-sX ",
        "ack": "-sA ",
        'udp_scan': '-sU ',
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
        "none": " "

    }

    return ping_options.get(ping_name)


class NcrackScanView(BaseView):
    key_options = ["Authentication", "MISC"]
    advance_options = \
        [
            {

                "Authentication": {

                    "Iterate password list for each username. Default is opposite.": "--passwords-first",
                    "Choose usernames and passwords in pairs.": "--pairwise",
                }
            },

            {

                "MISC": {

                    "quit cracking service after one found credential": "-f",
                    "Enable IPv6 cracking": "-6",
                    "only list hosts and services": "--list",
                },
            }

        ]

    form_error = None

    def get_list_of_website(self):
        website_repo = WebsiteRepository(db, Website)
        list_of_website = website_repo.list()
        return list_of_website

    @expose('/', methods=['GET', 'POST'])
    def index(self):

        return self.render(
            'ncrack_scan.html',
            websites=self.get_list_of_website(),
            # advance_options=self.advance_options,
            error_forms=self.form_error or None)

    @expose('/', methods=['POST'])
    def get_index(self):
        logging.error(" dvdvfvfvfvf website_name ")
        form = request.form
        logging.warning(form)
        website_checked = form.get('website_name')
        username = form.get('username')
        password = form.get('password')
        if not username and not password:
            self.form_error = "Please enter username and password"
            return self.render(
                'ncrack_scan.html',
                websites=self.get_list_of_website(),
                # advance_options=self.advance_options,
                error_forms=self.form_error or None)

        if website_checked:
            website_repo = WebsiteRepository(db, Website)
            website_id = UUID(website_checked)
            website = website_repo.find(website_id)
            logging.error(website)
            args: str = ""
            if website:
                args_user = username if username else ""
                args_pass = password if password else ""
                logging.warning(args)
                result_of_scan = ncrack_launch_scan(website.url, args_user, args_pass, "--user", "--pass")

                return self.render(
                    'ncrack_scan.html',
                    websites=self.get_list_of_website(),
                    result_of_scan=result_of_scan[0].split("\n"),
                    error_during_scan=result_of_scan[1].split("\n"),
                    error_forms=self.form_error or None)
        else:
            self.form_error = "Please choise your website"
            return self.render(
                'ncrack_scan.html',
                websites=self.get_list_of_website(),
                error_forms=self.form_error or None)

    @expose('/okay', methods=['GET', 'POST'])
    def up_load_file(self):
        if request.method == "POST":
            form = request.form
            logging.warning(form)
            website_checked = form.get('website_name')
            if not request.files.get('username_file') and not request.files.get('password_file'):
                self.form_error = 'No file part'
                return self.render(
                    'ncrack_scan.html',
                    websites=self.get_list_of_website(),
                    error_forms=self.form_error or None)

            request_pass = request.files.get('password_file')
            logging.info(request.files)
            password_file = None if request.files.get('password_file').filename == "" else request_pass
            request_user = request.files.get('username_file')
            username_file = None if request.files.get('password_file').filename == "" else request_user

            logging.info(username_file)
            if not username_file and not password_file:
                self.form_error = 'No selected file'
                return redirect(request.url)
            username_file_path = self.get_file(username_file)
            password_file_path = self.get_file(password_file)
            logging.warning(username_file_path)
            logging.warning(password_file_path)
            if website_checked:
                website_repo = WebsiteRepository(db, Website)
                website_id = UUID(website_checked)
                website = website_repo.find(website_id)
                logging.error(website)
                args: str = ""
                if website:
                    result_of_scan = ncrack_launch_scan(
                        website.url, username_file_path, password_file_path, "-U", "-P")

                    return self.render(
                        'ncrack_scan.html',
                        websites=self.get_list_of_website(),
                        result_of_scan=result_of_scan[0].split("\n"),
                        error_during_scan=result_of_scan[1].split("\n"),
                        error_forms=self.form_error or None)
            else:

                self.form_error = "Please choise your website"
                return self.render(
                    'ncrack_scan.html',
                    websites=self.get_list_of_website(),
                    error_forms=self.form_error or None)
        return self.index()

    def get_file(self, file):
        logging.error(file)
        original_filename = file.filename
        extension = original_filename.rsplit('.', 1)[1].lower()
        filename = str(uuid.uuid1()) + '.' + extension
        file_path = mkdir_file_path(BaseConfig.UPLOAD_FOLDER)
        file_path = os.path.join(file_path, filename)
        if os.path.exists(BaseConfig.UPLOAD_FOLDER):
            file.save(file_path)
        else:
            os.mkdir(BaseConfig.UPLOAD_FOLDER)
            file.save(file_path)

        logging.warning(filename)
        logging.warning(file_path)
        return file_path


def mkdir_file_path(file_path):
    if os.path.exists(file_path):
        return file_path
    else:
        os.mkdir(file_path)
        return file_path
