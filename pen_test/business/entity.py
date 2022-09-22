from typing import List, Optional, Dict
from uuid import UUID, uuid4
from dataclasses import dataclass, field

from pen_test.business.interfaces.ianomalies import IAnomalies
from pen_test.business.interfaces.iscaninfo import INmapScanInfo
from pen_test.business.interfaces.iscanresult import INmapScanResult
from pen_test.business.interfaces.ivulnerability import IVulnerability
from pen_test.business.interfaces.iwebsite import IWebsite


@dataclass
class WebsiteEntity(IWebsite):
    url: str
    name: str = ''
    id: UUID = field(default=uuid4())
    host_ip: str = ''


    @classmethod
    def factory(cls, name: str, url: str, host_ip, id: Optional[UUID] = None) -> IWebsite:
        uuid = id or uuid4()
        obj = cls(
            id=uuid,
            name=name,
            url=url,
            host_ip=host_ip
        )
        return obj


@dataclass(frozen=True)
class AnomaliesEntity(IAnomalies):

    name: str
    number: int
    details: dict = field(default_factory=dict)
    id: UUID = field(default=uuid4())
    website_id: UUID = field(default=uuid4())

    @classmethod
    def factory(
            cls, website_id: UUID, name: str, number: int, details: Dict, id: Optional[UUID] = None
    ) -> IAnomalies:
        uuid = id or uuid4()
        anomaly = cls(
            id=uuid,
            website_id=website_id,
            name=name,
            number=number,
            details=details
        )
        return anomaly


@dataclass(frozen=True)
class VulnerabilityEntity(IVulnerability):
    id: UUID = field(default=uuid4())
    website_id: UUID = field(default=uuid4())
    attack_name: str = ''
    num_vulnerability: int = 0
    attack_details: dict = field(default_factory=dict)

    @classmethod
    def factory(
            cls,
            website_id: UUID,
            attack_name: str,
            num_vulnerability: int,
            attack_details: Dict,
            id: Optional[UUID] = None
    ) -> IVulnerability:
        uuid = id or uuid4()
        vul = cls(
            id=uuid,
            website_id=website_id,
            attack_name=attack_name,
            num_vulnerability=num_vulnerability,
            attack_details=attack_details
        )
        return vul


@dataclass(frozen=True)
class NmapScanResultEntity(INmapScanResult):

    scan_id:UUID
    protocol: str
    port: str
    name: str
    state: str
    product: str
    extra_info: str
    reason: str
    version: int
    conf: int
    cpe: int
    id: UUID = field(default=uuid4())

    @classmethod
    def factory(
            cls,

            scan_id:UUID,
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

    ) -> INmapScanResult:
        uuid = uuid or uuid4()
        nmap_scan = cls(
            id=uuid,
            scan_id=scan_id,
            protocol=protocol,
            port=port,
            name=name,
            state=state,
            product=product,
            extra_info=extra_info,
            reason=reason,
            version=version,
            conf=conf,
            cpe=cpe
        )
        return nmap_scan


@dataclass
class NmapScanInfoEntity(INmapScanInfo):
    website_id: UUID
    arguments: str
    ports: str
    id: UUID = field(default=uuid4())

    @classmethod
    def factory(
            cls, website_id: UUID, arguments: str, ports: str, uuid: Optional[UUID] = None
    ) -> INmapScanInfo:
        uuid = uuid or uuid4()
        scan_info = cls(
            id=uuid,
            website_id=website_id,
            arguments=arguments,
            ports=ports)

        return scan_info
