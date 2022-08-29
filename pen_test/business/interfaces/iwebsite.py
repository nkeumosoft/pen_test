import abc
from typing import Optional
from uuid import UUID


class IWebsite(metaclass=abc.ABCMeta):
    @abc.abstractproperty
    def uuid(self) -> UUID:
        ...

    @abc.abstractproperty
    def name(self) -> str:
        ...

    @abc.abstractproperty
    def url(self) -> str:
        ...

    @classmethod
    def factory(cls, name: str, url: str, uuid: Optional[UUID] = None) -> 'IWebsite':
        ...
