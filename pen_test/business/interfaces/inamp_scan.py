import abc


class IScanPort(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def scan(self, host, ports: str = None):
        ...
