import abc
from typing import List
from uuid import UUID

from pen_test.business.interfaces.iscanresult import INmapScanResult


class INmapScanResultRepository(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def find(self, uuid: UUID) -> INmapScanResult:
        ...

    @abc.abstractmethod
    def find_by_url(self, url: str) -> INmapScanResult:
        ...

    @abc.abstractmethod
    def create(self, nmap_result_website: INmapScanResult) -> INmapScanResult:
        ...

    @abc.abstractmethod
    def list(self) -> List[INmapScanResult]:
        ...
