import abc


class IPentTest(metaclass=abc.ABCMeta):
    url: str

    @abc.abstractmethod
    def execute(self):
        ...

    @property
    def url(self):
        ...


class IScan(abc.ABC):

    @abc.abstractmethod
    def scann(self):
        ...
