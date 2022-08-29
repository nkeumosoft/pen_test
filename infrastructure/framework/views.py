import asyncio

from flask import request, redirect, url_for
from flask_admin import expose, BaseView

from infrastructure.framework import db
from infrastructure.framework.forms import WebsiteForm
from infrastructure.framework.models import PenTestVulnerability, PentestAnomalies, Website
from infrastructure.repository.anomalies_repos import AnomaliesRepository
from infrastructure.repository.vulnerability_repos import VulnerabilityRepository
from infrastructure.repository.website_repository import WebsiteRepository
from pen_test.business.use_cases.pentest import PentTestRun
from pen_test.business.use_cases.pentest_result import PenTestResult


class Home(BaseView):
    @expose('/', methods=['GET', 'POST'])
    def index(self):
        form = WebsiteForm()
        if form.validate_on_submit():
            website_repo = WebsiteRepository(db, Website)
            vul_repo = VulnerabilityRepository(db, PenTestVulnerability)
            anomaly_repo = AnomaliesRepository(db, PentestAnomalies)
            pen_test = PentTestRun(website_repo, vul_repo, anomaly_repo, form.data['url'], form.data['name'])
            asyncio.run(pen_test.run())
            return redirect(url_for('/admin'))
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
            return self.render('result.html', request=request, name=Vulnerabilities,
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
                           vulnerabilities=anomalies)

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
            return self.render('result.html', request=request, name="anomalies",
                               vulnerabilities=anomalies_details)

        return redirect('/')
