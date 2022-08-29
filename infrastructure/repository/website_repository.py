from uuid import UUID

from flask_sqlalchemy import SQLAlchemy

from infrastructure.framework.models import Website
from pen_test.business.entity import WebsiteEntity
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

    @staticmethod
    def _factory_website(instance: Website) -> WebsiteEntity:
        return WebsiteEntity.factory(
            id=instance.id,
            name=instance.name,
            url=instance.url
        )

