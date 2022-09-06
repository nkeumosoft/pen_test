import json
import logging

from flask import redirect, request, url_for

from flask_admin import AdminIndexView, BaseView, expose
from flask_paginate import Pagination, get_page_parameter

from infrastructure.framework import db
from infrastructure.framework.forms import WebsiteForm
from infrastructure.framework.models import PenTestVulnerability, PentestAnomalies, Website
from infrastructure.repository.anomalies_repos import AnomaliesRepository
from infrastructure.repository.vulnerability_repos import VulnerabilityRepository
from infrastructure.repository.website_repository import WebsiteRepository
from pen_test.business.entity import WebsiteEntity
from pen_test.business.use_cases.crud_website import create_website, update_website
from pen_test.business.use_cases.pentest import PentTestRun
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
            thread_number = int(len(form)/2)

            scan_list_website(form, thread_number)
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

            website_find = website_repo.find_by_url(form.date.get("url"))
            if not website_find:
                website_find = WebsiteEntity(url=form.date.get("url"), name=form.date.get("name"))

                create_website(website_find)
            else:
                website_find.url = form.date.get("url")
                website_find.name = form.data.get("name")
                update_website(website_find)

            return redirect(url_for('admin.index'))

            # vul_repo = VulnerabilityRepository(db, PenTestVulnerability)
            # anomaly_repo = AnomaliesRepository(db, PentestAnomalies)
            # pen_test = PentTestRun(website_repo, vul_repo, anomaly_repo, )
            # pen_test.run()

        return self.render('website.html', request=request, form=form)


class Vulnerabilities(BaseView):
    @expose('/')
    def index(self):
        vul_repo = VulnerabilityRepository(db=db, model=PenTestVulnerability)
        anomalies_repo = AnomaliesRepository(db=db, model=PentestAnomalies)

        pent_result = PenTestResult(
            _url='',
            _vul_repo=vul_repo,
            _anomaly_repo=anomalies_repo,
        )
        vulnerabilities = pent_result.list_vul()

        return self.render('vulnerabilities_result.html', request=request, name="Vulnerabilities",
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
        vul_repo = VulnerabilityRepository(db=db, model=PenTestVulnerability)

        url = request.form.get("search")
        website_repo = WebsiteRepository(db, Website)

        if url:
            website = website_repo.find(url)
            if website:
                vulnerabilities = vul_repo.filter_list_by_website(website.id)
        logging.error(vulnerabilities)
        return self.render('vulnerabilities_result.html',
                           request=request,
                           name="Vulnerabilities",
                           vulnerabilities=vulnerabilities)


class Anomalies(BaseView):

    @expose('/')
    def index(self):
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

        return self.render('anomalies_result.html', request=request, name="anomalies",
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

        anomalies_repo = AnomaliesRepository(db=db, model=PentestAnomalies)
        url = request.form.get("search")
        website_repo = WebsiteRepository(db, Website)
        anomalies = []
        if url:
            website = website_repo.find(url)
            if website:
                anomalies = anomalies_repo.filter_list_by_website(website.id)
        logging.error(anomalies)
        return self.render('anomalies_result.html', request=request, name="Anomalies", anomalies=anomalies)


