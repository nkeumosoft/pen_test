from dataclasses import dataclass

from wapitiCore.attack.mod_wp_enum import ModuleWpEnum

from pen_test.business.interfaces.ipen_test import IScan


@dataclass(frozen=True)
class WPScan(IScan):

    def scann(self):
        ...

    def execute(self):
        ...


@dataclass(frozen=True)
class CMSScanner(IScan):

    def scann(self):
        ...

    def execute(self):
        ...
