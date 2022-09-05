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
            return redirect(url_for('home.index'))

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
        list_of_website = website_repo.list()

        return self.render('result.html', websites=list_of_website)


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
            else:
                website_find.url = form.data.get("url")
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

        return self.render('result.html', request=request, name="Vulnerabilities",
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

        return self.render('result.html', request=request, name="anomalies",
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
