import asyncio
from dataclasses import dataclass
from typing import Dict
from uuid import UUID

from pen_test.business.entity import AnomaliesEntity, VulnerabilityEntity, WebsiteEntity
from pen_test.business.interfaces.ianomalies_repos import IAnomaliesRepository
from pen_test.business.interfaces.ipen_test import IPentTestRun
from pen_test.business.interfaces.ivulnerability_repos import IVulnerabilityRepository
from pen_test.business.interfaces.iwebsite_repository import IWebsiteRepository
from pen_test.business.use_cases.attacks import InitPenTest


@dataclass
class we(IPentTestRun):
    _website_repo: IWebsiteRepository
    _vul_repo: IVulnerabilityRepository
    _anomaly_repo: IAnomaliesRepository
    _url: str
    _name: str

    def create_anomalies(self, anomaly: Dict, website_id: UUID) -> None:
        key_dict = anomaly.keys()
        output = []
        for key in key_dict:
            a = AnomaliesEntity.factory(
                website_id=website_id,
                name=key,
                number=len(anomaly[key]),
                details=anomaly[key]
            )
            anomaly_ent = self._anomaly_repo.create(a)
            output.append(anomaly_ent)

    def create_vul(self, vul: Dict, website_id: UUID) -> None:
        keys = vul.keys()
        output = []
        for key in keys:
            v = VulnerabilityEntity.factory(
                website_id=website_id,
                attack_name=key,
                num_vulnerability=len(vul[key]),
                attack_details=vul[key],
            )
            vul_ent = self._vul_repo.create(v)
            output.append(vul_ent)

    def run(self):
        website = self._website_repo.find_by_url(url=self._url)
        if not website:
            website_ent = WebsiteEntity.factory(name=self._name, url=self._url)
            website = self._website_repo.create(website_ent)
        pen_test = InitPenTest(website.url)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(pen_test.execute())
        loop.close()
        self.create_vul(result['_vulns'], website.id)
        self.create_anomalies(result['_anomalies'], website.id)
