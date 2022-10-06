import logging
import subprocess


class SqlMapScanner:
    def __init__(self, url):
        self._url = url

    def scan(self) -> str:
        subprocess.run(["sqlmap", "-u", self._url, "--batch"])  # A enlever

        logging.info("Waiting for sqlmap to finish to capture the result ...")
        result = subprocess.run(["sqlmap", "-u", self._url + "?id=1", "--batch"], capture_output=True)

        return result.stdout.decode()


if __name__ == "__main__":
    scanner = SqlMapScanner("https://fr.wikipedia.org/wiki/Wikip%C3%A9dia:Accueil_principal")
    print(scanner.scan())
