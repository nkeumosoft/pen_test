from typing import List
from uuid import UUID

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc

from infrastructure.framework.models import NmapResult
from pen_test.business.entity import NmapScanResultEntity
from pen_test.business.interfaces.iscanresult_repo import \
    INmapScanResultRepository


class NmapResultRepository(INmapScanResultRepository):
    def __init__(self, db: SQLAlchemy, model: NmapResult):
        self._model = model
        self._db = db

    def find(self, uuid: UUID) -> NmapScanResultEntity:
        instance = self._model.query.get(uuid)
        if instance:
            return self._factory_nmap_result(instance)

    def find_by_url(self, url: str) -> NmapScanResultEntity:
        instance = self._model.query.filter_by(url=url).first()
        if instance:
            return self._factory_nmap_result(instance)

    def create(
        self, nmap_result_website: NmapScanResultEntity
    ) -> NmapScanResultEntity:
        instance = self._model(
            scan_id=nmap_result_website.scan_id,
            protocol=nmap_result_website.protocol,
            port=nmap_result_website.port,
            name=nmap_result_website.name,
            state=nmap_result_website.state,
            product=nmap_result_website.product,
            extra_info=nmap_result_website.extra_info,
            reason=nmap_result_website.reason,
            version=nmap_result_website.version,
            conf=nmap_result_website.conf,
            cpe=nmap_result_website.cpe,
        )
        self._db.session.add(instance)
        self._db.session.commit()
        return self._factory_nmap_result(instance)

    def update(
        self, nmap_result_website: NmapScanResultEntity
    ) -> NmapScanResultEntity:
        instance = self._model.query.filter(id=nmap_result_website.id).first()
        instance.scan_id = nmap_result_website.scan_id
        instance.protocol = nmap_result_website.protocol
        instance.port = nmap_result_website.port
        instance.name = nmap_result_website.name
        instance.state = nmap_result_website.state
        instance.product = nmap_result_website.product
        instance.extra_info = nmap_result_website.extra_info
        instance.reason = nmap_result_website.reason
        instance.version = nmap_result_website.version
        instance.conf = nmap_result_website.conf
        instance.cpe = nmap_result_website.cpe

        self._db.session.commit()

        return self._factory_nmap_result(instance)

    def list(self) -> List[NmapScanResultEntity]:
        instances = self._model.query.order_by(
            desc(self._model.created_date)
        ).all()

        return [self._factory_nmap_result(instance) for instance in instances]

    @staticmethod
    def _factory_nmap_result(instance: NmapResult) -> NmapScanResultEntity:
        return NmapScanResultEntity.factory(
            uuid=instance.id,
            scan_id=instance.scan_id,
            protocol=instance.protocol,
            port=instance.port,
            name=instance.name,
            state=instance.state,
            product=instance.product,
            extra_info=instance.extra_info,
            reason=instance.reason,
            version=instance.version,
            conf=instance.conf,
            cpe=instance.cpe,
        )
