import asyncio
import json
import logging
import sys
from dataclasses import dataclass
from sqlite3 import OperationalError

from wapitiCore.language.language import _
from wapitiCore.main.wapiti import (InvalidOptionValue, fix_url_path,
                                    is_valid_endpoint)
from wapitiCore.net.web import Request

from business.wapitiapi import WapitiWeb


@dataclass
class WpPentest:
    _url: str

    @property
    def url(self):
        return self._url

    @url.setter
    def url(self, url: str):
        self._url = url

    async def execute(self, modules=None):
        global_stop_event = asyncio.Event()
        scope = "folder"
        store_session = store_config = None

        wapiti = WapitiWeb(
            scope_request=Request(self._url),
            scope=scope,
            session_dir=store_session,
            config_dir=store_config,
        )

        try:
            depth = 40
            max_file_per_dir = 0
            max_link_per_page = 100
            scan_force = "normal"
            max_scan_time = 0
            max_attack_time = 0

            wapiti.set_max_depth(depth)
            wapiti.set_max_files_per_dir(max_file_per_dir)
            wapiti.set_max_links_per_page(max_link_per_page)
            wapiti.set_scan_force(scan_force)
            wapiti.set_max_scan_time(max_scan_time)
            wapiti.set_max_attack_time(max_attack_time)

            verbosity = 0
            timeout = 6.0

            if modules is None:
                modules = "common"

            wapiti.verbosity(verbosity)
            wapiti.set_color()
            wapiti.set_timeout(timeout=timeout)
            wapiti.set_modules(modules)

            format_generator = "html"
            check_ssl = False
            level = 1
            tasks = 32

            wapiti.set_report_generator_type(format_generator)
            wapiti.set_verify_ssl(check_ssl)

            attack_options = {
                "level": level,
                "timeout": timeout,
                "tasks": tasks,
            }

            dns_endpoint = "dns.wapiti3.ovh"
            endpoint = "https://wapiti3.ovh/"

            attack_options["dns_endpoint"] = dns_endpoint
            endpoint = fix_url_path(endpoint)
            if is_valid_endpoint("ENDPOINT", endpoint):
                attack_options["external_endpoint"] = endpoint
                attack_options["internal_endpoint"] = endpoint
            else:
                raise InvalidOptionValue("--endpoint", endpoint)

            wapiti.set_attack_options(attack_options)
            await wapiti.init_persister()
            await wapiti.init_crawler()

        except InvalidOptionValue as msg:
            logging.error(msg)
            sys.exit(2)

        try:
            if await wapiti.have_attacks_started() and True:
                pass
            else:
                await wapiti.load_scan_state()
                await wapiti.browse(global_stop_event, parallelism=32)
                await wapiti.save_scan_state()

            await wapiti.attack(global_stop_event)
            attack_results = await wapiti.get_result()
            print(json.dumps(attack_results))

        except OperationalError:
            logging.error(
                _(
                    "[!] Can't store information in persister. SQLite database"
                    " must have been locked by another process"
                )
            )
            logging.error(_("[!] You should unlock and launch Wapiti again."))
        except SystemExit:
            pass


if __name__ == "__main__":
    web = WpPentest("https://www.tesla.com/")
    asyncio.run(web.execute("drupal_enum"))
