from typing import List
from uuid import UUID

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc

from infrastructure.framework.models import NmapScanInfo
from pen_test.business.entity import NmapScanInfoEntity
from pen_test.business.interfaces.iscanresult_repo import \
    INmapScanResultRepository


class NmapScanInfoRepository(INmapScanResultRepository):
    def __init__(self, db: SQLAlchemy, model: NmapScanInfo):
        self._model = model
        self._db = db

    def find(self, uuid: UUID) -> NmapScanInfoEntity:
        instance = self._model.query.get(uuid)
        if instance:
            return self._factory_nmap_info(instance)

    def find_by_url(self, url: str) -> NmapScanInfoEntity:
        instance = self._model.query.filter_by(url=url).first()
        if instance:
            return self._factory_nmap_info(instance)

    def create(self, nmap_website: NmapScanInfoEntity) -> NmapScanInfoEntity:
        instance = self.find(nmap_website.id)
        if not instance:
            instance = self._model(
                id=nmap_website.id,
                website_id=nmap_website.website_id,
                arguments=nmap_website.arguments,
                ports=nmap_website.ports,
            )
            self._db.session.add(instance)
            self._db.session.commit()
        return self._factory_nmap_info(instance)

    def update(self, nmap_website: NmapScanInfoEntity) -> NmapScanInfoEntity:
        instance = self._model.query.filter(id=nmap_website.id).first()
        instance.website_id = nmap_website.website_id
        instance.arguments = nmap_website.arguments
        instance.ports = nmap_website.ports

        self._db.session.commit()

        return self._factory_nmap_info(instance)

    def list(self) -> List[NmapScanInfoEntity]:
        instances = self._model.query.order_by(
            desc(self._model.created_date)
        ).all()

        return [self._factory_nmap_info(instance) for instance in instances]

    @staticmethod
    def _factory_nmap_info(instance: NmapScanInfo) -> NmapScanInfoEntity:
        return NmapScanInfoEntity.factory(
            uuid=instance.id,
            website_id=instance.website_id,
            arguments=instance.arguments,
            ports=instance.ports,
        )
