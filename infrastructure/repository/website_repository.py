import logging
from typing import List
from uuid import UUID

from flask_sqlalchemy import SQLAlchemy

from infrastructure.framework.models import PenTestVulnerability, PentestAnomalies, Website
from pen_test.business.entity import AnomaliesEntity, VulnerabilityEntity, WebsiteEntity
from pen_test.business.interfaces.iwebsite_repository import IWebsiteRepository


class WebsiteRepository(IWebsiteRepository):

    def __init__(self, db: SQLAlchemy, model: Website):
        self._model = model
        self._db = db

    def find(self, uuid: UUID) -> WebsiteEntity:
        instance = self._model.query.get(uuid)
        if instance:
            return self._factory_website(instance)

    def find_by_url(self, url: str) -> WebsiteEntity:
        instance = self._model.query.filter_by(url=url).first()
        if instance:
            return self._factory_website(instance)

    def create(self, website: WebsiteEntity) -> WebsiteEntity:
        instance = self._model(id=website.id, name=website.name, url=website.url)
        self._db.session.add(instance)
        self._db.session.commit()
        return self._factory_website(instance)

    # def add_vulnerability(self, id: UUID, vulnerability: List[PenTestVulnerability]) -> WebsiteEntity:
    #     instance = self._model.query.get(id)
    #     for vul in vulnerability:
    #
    #         vul = PenTestVulnerability.query.get(vul.id)
    #
    #         instance.vulnerabilities.append(vul)
    #     self._db.session.commit()
    #     return self._factory_website(instance)
    #
    # def add_anomalies(self, id: UUID, anomalies: List[PentestAnomalies]) -> WebsiteEntity:
    #     instance = self._model.query.get_or_404(id)
    #     logging.warning(anomalies)
    #     for anomaly in anomalies:
    #         logging.warning('======================')
    #         anomaly = PentestAnomalies.query.get(anomaly.id)
    #         logging.warning(anomalies)
    #         instance.anomalies.append(anomaly)
    #
    #     self._db.session.commit()
    #     return self._factory_website(instance)

    @staticmethod
    def _factory_website(instance: Website) -> WebsiteEntity:
        return WebsiteEntity.factory(
            id=instance.id,
            name=instance.name,
            url=instance.url,

        )
