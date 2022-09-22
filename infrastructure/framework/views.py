import logging
import socket

from flask import redirect, request, url_for
from flask_admin import AdminIndexView, BaseView, expose
from flask_paginate import Pagination, get_page_parameter

from infrastructure.framework import db
from infrastructure.framework.forms import NmapScanForm, SearchForm, WebsiteForm
from infrastructure.framework.models import PenTestVulnerability, PentestAnomalies, Website
from infrastructure.repository.anomalies_repos import AnomaliesRepository
from infrastructure.repository.vulnerability_repos import VulnerabilityRepository
from infrastructure.repository.website_repository import WebsiteRepository
from pen_test.business.entity import WebsiteEntity
from pen_test.business.use_cases.crud_website import create_website
from pen_test.business.use_cases.nmap_scan_port import NmapScanPort
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

        return self.render('run_pentest.html',  websites=list_of_website, pagination=pagination)

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
        form = NmapScanForm()

        if form.validate_on_submit():

            url = form.data.get("host")
            start_port = form.data.get("start_port")
            end_port = form.data.get("end_port")
            logging.warning(f"{url}: {start_port} {end_port}")

            try:
                ip = socket.gethostbyname(url)
                logging.warning(ip)
                nmap_scaner = NmapScanPort(host=ip, port=f"{str(start_port)}-{str(end_port)}")
                nmap_scaner.async_scan()
                return redirect(url_for('nmapscanview.index'))
            except socket.gaierror:
                logging.error('Name or service not known')
                nmap_scaner = NmapScanPort(host=url, port=f"{str(start_port)}-{str(end_port)}")

            nmap_scaner.async_scan()
        return self.render('nmap_scan.html', form=form)