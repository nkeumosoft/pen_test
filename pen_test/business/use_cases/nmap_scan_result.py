from typing import List
from uuid import UUID

from infrastructure.framework import db
from infrastructure.framework.models import NmapResult
from infrastructure.repository.nmapscanresult_repo import NmapResultRepository
from pen_test.business.entity import NmapScanResultEntity


def update_nmap_scan_result(nmap_scan_info_entity: NmapScanResultEntity) -> NmapScanResultEntity:
    """Update a nmap_scan_info."""

    nmap_scan_info = NmapResultRepository(db, NmapResult)

    return nmap_scan_info.update(nmap_scan_info_entity)


def get_list_namp(web: UUID) -> NmapScanResultEntity:
    nmap_scan_info = NmapResultRepository(db, NmapResult)

    return nmap_scan_info.find(web)


def list_nmap_result() -> List[NmapScanResultEntity]:
    """Update a nmap_scan_info."""

    nmap_scan_info = NmapResultRepository(db, NmapResult)

    return nmap_scan_info.list()


def create_nmap_scan_result(nmap_scan_info_entity: NmapScanResultEntity) -> NmapScanResultEntity:
    nmap_scan_info = NmapResultRepository(db, NmapResult)

    return nmap_scan_info.create(nmap_scan_info_entity)
