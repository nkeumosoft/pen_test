import abc
from typing import Dict, Optional
from uuid import UUID, uuid4


class IAnomalies(metaclass=abc.ABCMeta):

    @abc.abstractproperty
    def name(self) -> str:
        ...

    @abc.abstractproperty
    def number(self) -> int:
        ...

    @abc.abstractproperty
    def details(self) -> Dict:
        ...

    @abc.abstractproperty
    def uuid(self) -> UUID:
        ...

    @classmethod
    def factory(
            cls, website_id: UUID, name: str, number: int, details: Dict, uuid: Optional[UUID] = None
    ) -> 'IAnomalies':
        uuid = uuid or uuid4()
        return cls(
            uuid,
            website_id,
            name,
            number,
            details
        )
