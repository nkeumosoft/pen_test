import asyncio
import logging
import os
import sys
from dataclasses import dataclass, field
from sqlite3 import OperationalError

import httpx

from datetime import datetime
from uuid import uuid1

from httpx import RequestError

from wapitiCore import WAPITI_VERSION
from wapitiCore.main.wapiti import Wapiti, fix_url_path, is_valid_endpoint, InvalidOptionValue
from wapitiCore.language.language import _
from wapitiCore.net import Request


class PenTestAttacks(Wapiti):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    async def attack(self, stop_event: asyncio.Event):
        """Launch the attacks based on the
        preferences set by the command line"""

        await self._init_attacks(stop_event)

        answer = "0"

        for attack_module in self.attacks:
            if stop_event.is_set():
                break

            start = datetime.utcnow()
            if attack_module.do_get is False \
                    and attack_module.do_post is False:
                continue

            if attack_module.require:
                attack_name_list = [attack.name for attack in self.attacks if
                                    attack.name in attack_module.require and
                                    (attack.do_get or attack.do_post)]
                if attack_module.require != attack_name_list:
                    logging.error(
                        _(
                            f"[!] Missing dependencies for module"
                            f" {attack_module.name}:"))
                    logging.error("  {0}", ",".join(
                        [attack for attack in attack_module.require if
                         attack not in attack_name_list]
                    ))
                    continue

                attack_module.load_require(
                    [attack for attack in self.attacks if
                     attack.name in attack_module.require]
                )

            logging.info("GREEN", _("[*] Launching module {0}"), attack_module.name)

            already_attacked = await self.persister.count_attacked(
                attack_module.name)
            if already_attacked:
                logging.info(_(
                    f"[*] {already_attacked} "
                    f"pages were previously attacked and will be skipped")
                )

            answer = "0"
            attacked_ids = set()
            async for original_request, original_response \
                    in self.load_resources_for_module(attack_module):
                if stop_event.is_set():
                    logging.info(_("Attack process was interrupted. Do you want to:"))
                    logging.info(_("\tr) stop everything here and generate the (R)eport"))
                    logging.info(_("\tn) move to the (N)ext attack module (if any)"))
                    logging.info(_("\tq) (Q)uit without generating the report"))
                    logging.info(_("\tc) (C)ontinue the current attack"))

                    while True:
                        try:
                            answer = input("? ").strip().lower()
                        except UnicodeDecodeError:
                            pass

                        if answer not in ("r", "n", "q", "c"):
                            logging.info(
                                _("Invalid choice. Valid "
                                  "choices are r, n, q and c."))
                        else:
                            break

                    if answer in ("n", "c"):
                        stop_event.clear()

                    if answer in ("r", "n", "q"):
                        break

                    if answer == "c":
                        continue
                try:
                    if await attack_module.must_attack(
                            original_request,
                            original_response
                    ):
                        logging.info(f"[+] {original_request}")

                        await attack_module.attack(original_request,
                                                   original_response)

                    if (
                            datetime.utcnow() - start).total_seconds() \
                            > self._max_attack_time >= 1:
                        logging.info(
                            _(f"Max attack time was reached for module "
                              f"{attack_module.name}, stopping.")
                        )
                        break
                except RequestError:
                    # Hmmm it should be caught inside the module
                    await asyncio.sleep(1)
                    continue
                except Exception as exception:
                    # Catch every possible exceptions and logging.info() it
                    exception_traceback = sys.exc_info()[2]
                    logging.exception(exception.__class__.__name__, exception)

                    if self._bug_report:
                        traceback_file = str(uuid1())
                        with open(traceback_file, "w", encoding='utf-8') as traceback_fd:
                            logging.info("exception traceback", exception_traceback)
                            logging.info(f"{exception.__class__.__name__}: {exception}")
                            logging.info(f"Occurred in {attack_module.name} on {original_request}")
                            logging.info(f"Wapiti {WAPITI_VERSION}. httpx {httpx.__version__}. OS {sys.platform}")

                        try:
                            with open(traceback_file,
                                      "rb") as traceback_byte_fd:
                                upload_request = Request(
                                    "https://wapiti3.ovh/upload.php",
                                    file_params=[
                                        ["crash_report",
                                         (traceback_file,
                                          traceback_byte_fd.read(),
                                          "text/plain")]
                                    ]
                                )
                            page = await self.crawler.async_send(
                                upload_request)
                            logging.success(
                                _(f"Sending crash report "
                                  f"{traceback_file} ... {page.content}"))
                        except RequestError:
                            logging.error(_("Error sending crash report"))
                        os.unlink(traceback_file)
                else:
                    if original_request.path_id is not None:
                        attacked_ids.add(original_request.path_id)

            await self.persister.set_attacked(attacked_ids, attack_module.name)

            if hasattr(attack_module, "finish"):
                await attack_module.finish()

            if attack_module.network_errors:
                logging.warning(
                    _(f"{attack_module.network_errors} requests were "
                      f"skipped due to network issues")
                )

            if answer == "r":
                # Do not process remaining modules
                break

        if answer == "q":
            await self.crawler.close()
            await self.persister.close()
            return

        async for payload in self.persister.get_payloads():
            if payload.type == "vulnerability":
                self.report_gen.add_vulnerability(
                    category=payload.category,
                    level=payload.level,
                    request=payload.evil_request,
                    parameter=payload.parameter,
                    info=payload.info,
                    module=payload.module,
                    wstg=payload.wstg,
                    response=payload.response
                )
            elif payload.type == "anomaly":
                self.report_gen.add_anomaly(
                    category=payload.category,
                    level=payload.level,
                    request=payload.evil_request,
                    parameter=payload.parameter,
                    info=payload.info,
                    module=payload.module,
                    wstg=payload.wstg,
                    response=payload.response
                )
            elif payload.type == "additional":
                self.report_gen.add_additional(
                    category=payload.category,
                    level=payload.level,
                    request=payload.evil_request,
                    parameter=payload.parameter,
                    info=payload.info,
                    module=payload.module,
                    wstg=payload.wstg,
                    response=payload.response
                )

        await self.crawler.close()
        await self.persister.close()

    async def get_result(self):

        return {
            '_vulns': self.report_gen._vulns,
            '_anomalies': self.report_gen._anomalies,
            '_additionals': self.report_gen._additionals,
        }


@dataclass
class InitPenTest:
    _url: str
    scope: str = field(default='folder')

    async def execute(self, modules=None):
        global_stop_event = asyncio.Event()
        scope = "folder"  # Different values ("page", "folder", "domain", "url", "punk")
        store_session = store_config = None

        wapiti = PenTestAttacks(
            scope_request=Request(self._url),
            scope=scope,
            session_dir=store_session,
            config_dir=store_config,
        )

        try:
            depth = 40
            max_file_per_dir = 0
            max_link_per_page = 100
            scan_force = "normal"  # Different values ("paranoid", "sneaky", "polite", "normal", "aggressive", "insane")
            max_scan_time = 0
            max_attack_time = 0

            wapiti.set_max_depth(depth)
            wapiti.set_max_files_per_dir(max_file_per_dir)
            wapiti.set_max_links_per_page(max_link_per_page)
            wapiti.set_scan_force(scan_force)
            wapiti.set_max_scan_time(max_scan_time)
            wapiti.set_max_attack_time(max_attack_time)

            verbosity = 0  # Different values (0, 1, 2)
            timeout = 6.0

            if modules is None:
                modules = "common"

            wapiti.verbosity(verbosity)
            wapiti.set_color()
            wapiti.set_timeout(timeout=timeout)
            wapiti.set_modules(modules)

            check_ssl = False
            level = 1  # Different value (1, 2)
            tasks = 32

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
            return attack_results

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


result = asyncio.run(InitPenTest('https://www.tesla.com/').execute('drupal_enum'))
