import abc
from typing import List
from uuid import UUID

from pen_test.business.interfaces.iscaninfo import INmapScanInfo


class INmapScanInfoRepository(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def find(self, uuid: UUID) -> INmapScanInfo:
        ...

    @abc.abstractmethod
    def find_by_url(self, url: str) -> INmapScanInfo:
        ...

    @abc.abstractmethod
    def create(self, website: INmapScanInfo) -> INmapScanInfo:
        ...

    @abc.abstractmethod
    def list(self) -> List[INmapScanInfo]:
        ...
