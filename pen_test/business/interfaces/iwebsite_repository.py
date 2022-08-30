import abc
from typing import List
from uuid import UUID

from infrastructure.framework.models import PenTestVulnerability, PentestAnomalies, Website
from pen_test.business.interfaces.ianomalies import IAnomalies
from pen_test.business.interfaces.ivulnerability import IVulnerability
from pen_test.business.interfaces.iwebsite import IWebsite


class IWebsiteRepository(metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def find(self, uuid: UUID) -> IWebsite:
        ...

    @abc.abstractmethod
    def find_by_url(self, url: str) -> IWebsite:
        ...

    @abc.abstractmethod
    def create(self, website: IWebsite) -> IWebsite:
        ...

    @abc.abstractmethod
    def add_vulnerability(self, id: UUID, vulnerability: List[PenTestVulnerability]) -> Website:
        ...

    @abc.abstractmethod
    def add_anomalies(self, id: UUID, anomalies: List[PentestAnomalies]) -> Website:
        ...
