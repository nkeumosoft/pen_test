import abc
from typing import Optional
from uuid import UUID


class INmapScanResult(metaclass=abc.ABCMeta):
    @classmethod
    def factory(
            cls,
            scan_id,
            protocol: str,
            port: str,
            name: str,
            state: str,
            product: str,
            extra_info: str,
            reason: str,
            version: int,
            conf: int,
            cpe: int,
            uuid: Optional[UUID] = None

    ) -> 'INmapScanResult':
        ...
