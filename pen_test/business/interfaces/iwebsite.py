import abc
from typing import Optional
from uuid import UUID


class IWebsite(metaclass=abc.ABCMeta):
    @property
    def uuid(self) -> UUID:
        ...

    @property
    def name(self) -> str:
        ...

    @property
    def url(self) -> str:
        ...

    @classmethod
    def factory(cls, name: str, url: str, uuid: Optional[UUID] = None) -> 'IWebsite':
        ...
