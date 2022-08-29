import abc
from typing import Dict, List
from uuid import UUID

from pen_test.business.entity import VulnerabilityEntity, AnomaliesEntity, WebsiteEntity


class IPentTestRun(metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def run(self):
        ...

    @abc.abstractmethod
    def create_vul(self, vul: Dict, website_id: UUID) -> VulnerabilityEntity:
        ...

    def create_anomalies(self, anomaly: Dict, website_id: UUID) -> AnomaliesEntity:
        ...


class IPenTestResult(metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def get_vul_by_uuid(self, uuid:UUID) -> VulnerabilityEntity:
        ...

    # @abc.abstractmethod
    # def get_vul_by_website(self, website: UUID) -> VulnerabilityEntity:
    #     ...

    @abc.abstractmethod
    def get_anomaly_by_uuid(self, uuid: UUID) -> AnomaliesEntity:
        ...

    # @abc.abstractmethod
    # def get_anomaly_by_website(self, website: UUID) -> AnomaliesEntity:
    #     ...

    @abc.abstractmethod
    def list_vul(self) -> List[VulnerabilityEntity]:
        ...

    @abc.abstractmethod
    def list_anomaly(self) -> List[AnomaliesEntity]:
        ...
