import abc
from typing import Optional
from uuid import UUID


class IWebsite(metaclass=abc.ABCMeta):

    @classmethod
    def factory(
            cls, name: str, url: str, uuid: Optional[UUID] = None
    ) -> 'IWebsite':
        ...
