import abc
from typing import List
from uuid import UUID

from pen_test.business.interfaces.ianomalies import IAnomalies


class IAnomaliesRepository(metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def find(self, uuid: UUID) -> IAnomalies:
        ...

    @abc.abstractmethod
    def find_by_name(self, name: str) -> IAnomalies:
        ...

    @abc.abstractmethod
    def find_detail(self, uuid: UUID) -> IAnomalies:
        ...

    @abc.abstractmethod
    def find_by_website(self, website: UUID) -> IAnomalies:
        ...

    @abc.abstractmethod
    def filter_list_by_website(self, website: UUID) -> List[IAnomalies]:
        ...

    @abc.abstractmethod
    def create(self, anomaly: IAnomalies) -> IAnomalies:
        ...

    @abc.abstractmethod
    def list(self) -> List[IAnomalies]:
        ...
