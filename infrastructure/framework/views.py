from flask import request, redirect
from flask_admin import expose, BaseView

from infrastructure.framework import db
from infrastructure.framework.forms import WebsiteForm
from infrastructure.framework.models import  PenTestVulnerability, PentestAnomalies
from infrastructure.repository.anomalies_repos import AnomaliesRepository
from infrastructure.repository.vulnerability_repos import VulnerabilityRepository
from pen_test.business.use_cases.pentest_result import PenTestResult


class Home(BaseView):
    @expose('/', methods=['GET', 'POST'])
    def index(self):
        form = WebsiteForm()
        if form.validate_on_submit():
            # website_repo = WebsiteRepository(db, Website)
            # vul_repo = VulnerabilityRepository(db, PenTestVulnerability)
            # anomaly_repo = AnomaliesRepository(db, PentestAnomalies)
            # pen_test = PentTestRun.__int__(
            #     website_repo=website_repo,
            #     vul_repo=vul_repo,
            #     anomaly_repo=anomaly_repo,
            #     url=form.data['url'],
            #     name=form.data['name']
            # )
            # pen_test.run()
            return redirect('/admin')
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
        return self.render('result.html', request=request, name="API_v1",
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
            return self.render('result.html', request=request, name="API_v1",
                               vulnerabilities=vulnerabilities)


class Anomalies(BaseView):

    @expose('/')
    def index(self):
        # vul_repo = VulnerabilityRepository(db=db,
        #                                    model=PenTestVulnerability)
        # anomalies_repo = AnomaliesRepository(db=db,
        #                                      model=PentestAnomalies)
        #
        # pent_result = PenTestResult(
        #     _url='',
        #     _vul_repo=vul_repo,
        #     _anomaly_repo=anomalies_repo,
        # )
        anomalies = [] #pent_result.list_anomaly()
        return self.render('result.html', request=request, name="API_v1",
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
            return self.render('result.html', request=request, name="API_v1",
                               vulnerabilities=anomalies_details)

        return redirect('/')
