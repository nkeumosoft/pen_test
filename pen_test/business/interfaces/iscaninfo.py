import abc
from typing import Optional
from uuid import UUID


class INmapScanInfo(metaclass=abc.ABCMeta):

    @classmethod
    def factory(
            cls, website_id: UUID, arguments: str, ports: str, uuid: Optional[UUID] = None
    ) -> 'INmapScanInfo':
        ...

