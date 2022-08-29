from typing import Dict, List
from uuid import UUID

from flask_sqlalchemy import SQLAlchemy

from infrastructure.framework.models import PentestAnomalies
from pen_test.business.entity import AnomaliesEntity
from pen_test.business.interfaces.ianomalies import IAnomalies
from pen_test.business.interfaces.ianomalies_repos import IAnomaliesRepository


class AnomaliesRepository(IAnomaliesRepository):

    def __init__(self, db: SQLAlchemy, model: PentestAnomalies):
        self._model = model
        self._db = db

    def find(self, uuid: UUID) -> AnomaliesEntity:
        instance = self._model.query.get(uuid)
        return self._factory_anomalies_entity(instance)

    def find_by_name(self, name: str) -> AnomaliesEntity:
        instance = self._model.query.filter_by(name=name).first()
        return self._factory_anomalies_entity(instance)

    def find_detail(self, uuid: UUID) -> Dict:
        instance = self._model.query.get(uuid)
        return self._factory_anomalies_entity(instance).details

    def find_by_website(self, website: UUID) -> IAnomalies:
        instance = self._model.query.filter_by(website_id=website).first()
        return self._factory_anomalies_entity(instance)

    def list(self) -> List[AnomaliesEntity]:
        instances = self._model.query.order_by(self._model.created_date).all()
        return [self._factory_anomalies_entity(instance) for instance in instances]

    def create(self, anomaly: AnomaliesEntity) -> AnomaliesEntity:
        instance = self._model.__int__(
            anomaly_id=anomaly.uuid,
            website_id=anomaly.website_id,
            name=anomaly.name,
            number=anomaly.number,
            details=anomaly.details
        )
        self._db.session.add(instance)
        self._db.session.commit()

    @staticmethod
    def _factory_anomalies_entity(instance: PentestAnomalies) -> AnomaliesEntity:
        return AnomaliesEntity.factory(
            uuid=instance.id,
            website_id=instance.website_id,
            name=instance.name,
            number=instance.number,
            details=instance.details
        )

