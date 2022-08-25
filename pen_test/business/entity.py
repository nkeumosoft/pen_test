from typing import Optional
from uuid import UUID, uuid4
from dataclasses import dataclass

from pen_test.business.interfaces.iwebsite import IWebsite


@dataclass
class WebsiteEntity:
    uuid: UUID
    name: str
    url: str

    @property
    def uuid(self) -> UUID:
        return self.uuid

    @property
    def name(self) -> str:
        return self.name

    @property
    def url(self) -> str:
        return self.url

    @classmethod
    def factory(cls, name: str, url: str, uuid: Optional[UUID]=None) -> IWebsite:
        uuid = uuid or uuid4()
        obj = cls(
            uuid=uuid,
            name=name,
            url=url
        )
        return obj

