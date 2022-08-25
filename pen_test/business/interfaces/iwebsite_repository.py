import abc
from uuid import UUID

from pen_test.business.interfaces.iwebsite import IWebsite


class IWebsiteRepository(metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def find(self, uuid: UUID) -> IWebsite:
        ...

    @abc.abstractmethod
    def find_by_url(self, url: str) -> IWebsite:
        ...

    @abc.abstractmethod
    def create(self, website: IWebsite) -> IWebsite:
        ...
