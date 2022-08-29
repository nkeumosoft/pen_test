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


class Home(BaseView):
    @expose('/', methods=['GET', 'POST'])
    def index(self):
        form = WebsiteForm()
        if form.validate_on_submit():
            website_repo = WebsiteRepository(db, Website)
            vul_repo = VulnerabilityRepository(db, PenTestVulnerability)
            anomaly_repo = AnomaliesRepository(db, PentestAnomalies)
            pen_test = PentTestRun(website_repo, vul_repo, anomaly_repo, form.url.data, form.name.data)
            asyncio.run(pen_test.run())
            return redirect(url_for('/admin'))
        return self.render('website.html', request=request, form=form)




