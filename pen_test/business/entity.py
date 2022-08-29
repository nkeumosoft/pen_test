from typing import Optional, Dict
from uuid import UUID, uuid4
from dataclasses import dataclass, field

from pen_test.business.interfaces.ianomalies import IAnomalies
from pen_test.business.interfaces.ivulnerability import IVulnerability
from pen_test.business.interfaces.iwebsite import IWebsite


@dataclass
class WebsiteEntity(IWebsite):
    url: str
    name: str = ''
    uuid: UUID = field(default=uuid4())

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
    def factory(cls, name: str, url: str, uuid: Optional[UUID] = None) -> IWebsite:
        uuid = uuid or uuid4()
        obj = cls(
            uuid=uuid,
            name=name,
            url=url
        )
        return obj


@dataclass(frozen=True)
class AnomaliesEntity(IAnomalies):
    website_id: UUID
    name: str
    number: int
    details: dict = field(default_factory=dict)
    uuid: UUID = field(default=uuid4())

    @property
    def name(self) -> str:
        return self.name

    @property
    def number(self) -> int:
        return self.number

    @property
    def details(self) -> Dict:
        return self.details

    @property
    def uuid(self) -> UUID:
        return self.uuid

    @classmethod
    def factory(
            cls, website_id: UUID, name: str, number: int, details: Dict, uuid: Optional[UUID] = None
    ) -> IAnomalies:
        uuid = uuid or uuid4()
        anomaly = cls(
            uuid,
            website_id,
            name,
            number,
            details
        )
        return anomaly


@dataclass(frozen=True)
class VulnerabilityEntity(IVulnerability):
    website_id: UUID
    attack_name: str
    num_vulnerability: int
    attack_details: dict = field(default_factory=dict)
    uuid: UUID = field(default=uuid4())

    @property
    def attack_name(self) -> str:
        return self.attack_name

    @property
    def num_vulnerability(self) -> int:
        return self.num_vulnerability

    @property
    def attack_details(self) -> Dict:
        return self.attack_details

    @property
    def uuid(self) -> UUID:
        return self.uuid

    @classmethod
    def factory(
            cls, website_id: UUID,
            attack_name: str,
            num_vulnerability: int,
            attack_details: Dict,
            uuid: Optional[UUID] = None
    ) -> IVulnerability:
        uuid = uuid or uuid4()
        vul = cls(
            uuid,
            website_id,
            attack_name,
            num_vulnerability,
            attack_details
        )
        return vul
