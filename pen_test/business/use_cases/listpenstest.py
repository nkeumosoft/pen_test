from _ast import List
from dataclasses import dataclass

from pen_test.business.entity import VulnerabilityEntity
from pen_test.business.interfaces.ipen_test import IPenTestResult
from pen_test.business.interfaces.iwebsite_repository import IWebsiteRepository
from pen_test.business.use_cases.pentest_result import PenTestResult


@dataclass
class ManyPenTestResult(IPenTestResult, PenTestResult):
    _website_repo: IWebsiteRepository

    def list_website(self) -> List[VulnerabilityEntity]:
        return self._website_repo.list()
