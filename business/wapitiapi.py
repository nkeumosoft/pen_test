import asyncio
import codecs
import json
import os
import signal
import sys
from datetime import datetime
from importlib import import_module
from inspect import getdoc
from sqlite3 import OperationalError
from traceback import print_tb
from urllib.parse import urlparse
from uuid import uuid1

import httpx
from httpx import RequestError

from wapitiCore import WAPITI_VERSION
from wapitiCore.attack.attack import (all_modules, common_modules)
from wapitiCore.language.language import _
from wapitiCore.main.log import logging
from wapitiCore.main.wapiti import Wapiti, fix_url_path, \
    InvalidOptionValue, is_valid_endpoint, ping, inner_ctrl_c_signal_handler, \
    global_stop_event, stop_attack_process
from wapitiCore.main.wapiti import module_to_class_name
from wapitiCore.net import Request
from wapitiCore.parsers.commandline import parse_args
from wapitiCore.report import GENERATORS


class WapitiWeb(Wapiti):
    """
        This class parse the options from the command line and
        set the modules and the HTTP engine accordingly.
        Launch wapiti without arguments or with the "-h"
        option for more information.
    """

    def __init__(self, *args, **kwargs):

        super(WapitiWeb, self).__init__(*args, **kwargs)

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

            logging.log("GREEN", _("[*] Launching module {0}"),
                        attack_module.name)

            already_attacked = await self.persister.count_attacked(
                attack_module.name)
            if already_attacked:
                logging.success(
                    _(f"[*] {already_attacked} pages were"
                      " previously attacked and will be skipped"),

                )

            answer = "0"
            attacked_ids = set()
            async for original_request, original_response \
                    in self.load_resources_for_module(
                attack_module):
                if stop_event.is_set():
                    print('')
                    print(_("Attack process was interrupted. Do you want to:"))
                    print(_("\tr) stop everything here and "
                            "generate the (R)eport"))
                    print(_("\tn) move to the (N)ext attack module (if any)"))
                    print(_("\tq) (Q)uit without generating the report"))
                    print(_("\tc) (C)ontinue the current attack"))

                    while True:
                        try:
                            answer = input("? ").strip().lower()
                        except UnicodeDecodeError:
                            pass

                        if answer not in ("r", "n", "q", "c"):
                            print(
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
                    if await attack_module.must_attack(original_request,
                                                       original_response):
                        logging.info(f"[+] {original_request}")

                        await attack_module.attack(original_request,
                                                   original_response)

                    if (
                            datetime.utcnow() - start).total_seconds() \
                            > self._max_attack_time >= 1:
                        # FIXME: Right now we cannot remove the pylint:
                        #  disable line because the current I18N system
                        # uses the string as a token so we cannot use f string
                        # pylint: disable=consider-using-f-string
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
                    # Catch every possible exceptions and print it
                    exception_traceback = sys.exc_info()[2]
                    logging.exception(exception.__class__.__name__, exception)

                    if self._bug_report:
                        traceback_file = str(uuid1())
                        with open(traceback_file, "w",
                                  encoding='utf-8') as traceback_fd:
                            print_tb(exception_traceback, file=traceback_fd)
                            print(
                                f"{exception.__class__.__name__}: {exception}",
                                file=traceback_fd)
                            print(
                                f"Occurred in {attack_module.name}"
                                f" on {original_request}",
                                file=traceback_fd)
                            logging.info(
                                f"Wapiti {WAPITI_VERSION}. httpx "
                                f"{httpx.__version__}. OS {sys.platform}")

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

        # if self.crawler.get_uploads():
        #     print('')
        #     print(_("Upload scripts found:"))
        #     print("----------------------")
        #     for upload_form in self.crawler.get_uploads():
        #         print(upload_form)

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

        # print('')
        # logging.log("GREEN", _("[*] Generating report..."))
        # self.report_gen.generate_report(self.output_file)
        # logging.success(
        #     _("A report has been generated in the file {0}").format(
        #         self.output_file))
        # if self.report_generator_type == "html":
        #     logging.success(
        #         _("Open {0} with a browser to see this report.").format(
        #             self.report_gen.final_path))

        await self.crawler.close()
        await self.persister.close()

    async def get_result(self):

        return {
            '_vulns': self.report_gen._vulns,
            '_anomalies': self.report_gen._anomalies,
            '_additionals': self.report_gen._additionals,
        }


async def wapiti_web_main(args):
    if args.tasks < 1:
        logging.error(_("Number of concurrent tasks must be 1 or above!"))
        sys.exit(2)

    if args.scope == "punk":
        print(_("[*] Do you feel lucky punk?"))

    if args.list_modules:
        print(_("[*] Available modules:"))
        for module_name in sorted(all_modules):
            try:
                mod = import_module("wapitiCore.attack.mod_" + module_name)
                class_name = module_to_class_name(module_name)
                is_common = " (used by default)" if module_name in common_modules else ""
                print(f"\t{module_name}{is_common}")
                print("\t\t" + getdoc(getattr(mod, class_name)))
                print('')
            except ImportError:
                continue
        sys.exit()

    url = fix_url_path(args.base_url)
    if args.data:
        base_requests = Request(
            url,
            method="POST",
            post_params=args.data
        )
    else:
        base_requests = Request(url)

    parts = urlparse(url)
    if not parts.scheme or not parts.netloc:
        logging.error(
            _("Invalid base URL was specified, please give a complete URL with protocol scheme."))
        sys.exit()
    logging.error(f"cmkfvmfkvmlvl {args}")
    wap = WapitiWeb(
        base_requests, scope=args.scope,
        session_dir=args.store_session, config_dir=args.store_config)

    # if args.log:
    #     wap.set_logfile(args.log)

    # if args.update:
    #     await wap.init_persister()
    #     await wap.init_crawler()
    #     logging.log("GREEN", _("[*] Updating modules"))
    #     attack_options = {"level": args.level, "timeout": args.timeout}
    #     wap.set_attack_options(attack_options)
    #     await wap.update(args.modules)
    #     await wap.crawler.close()
    #     sys.exit()
    logging.error('start url 925 ')
    try:
        for start_url in args.starting_urls:

            logging.error('start url 929 ')
            if start_url.startswith(("http://", "https://")):
                wap.add_start_url(start_url)
            elif os.path.isfile(start_url):
                try:
                    with codecs.open(start_url, encoding="UTF-8") as urlfd:
                        for urlline in urlfd:
                            urlline = urlline.strip()
                            if urlline.startswith(("http://", "https://")):
                                wap.add_start_url(urlline)
                except UnicodeDecodeError as exception:
                    logging.error(
                        _("Error: File given with the -s option must be UTF-8 encoded !"))
                    raise InvalidOptionValue("-s", start_url) from exception
            else:
                raise InvalidOptionValue('-s', start_url)

        logging.error('start url 945 ')
        for exclude_url in args.excluded_urls:
            if exclude_url.startswith(("http://", "https://")):
                wap.add_excluded_url(exclude_url)
            else:
                raise InvalidOptionValue("-x", exclude_url)

        if "proxy" in args:
            wap.set_proxy(args.proxy)

        if args.tor:
            wap.set_proxy("socks5://127.0.0.1:9050/")

        if "mitm_port" in args:
            wap.set_intercepting_proxy_port(args.mitm_port)

        if "cookie" in args:
            if os.path.isfile(args.cookie):
                wap.set_cookie_file(args.cookie)
            elif args.cookie.lower() in ("chrome", "firefox"):
                wap.load_browser_cookies(args.cookie)
            else:
                raise InvalidOptionValue("-c", args.cookie)

        if args.drop_set_cookie:
            wap.set_drop_cookies()

        auth_credentials = tuple()
        if "credentials" in args:
            if "auth_type" not in args:
                raise InvalidOptionValue("--auth-type",
                                         "This option is required when -a is used")
            if "%" in args.credentials:
                auth_credentials = args.credentials.split("%", 1)
                wap.set_auth_credentials(auth_credentials)
            else:
                raise InvalidOptionValue("-a", args.credentials)

        auth_url = ""
        if "auth_type" in args:
            if "credentials" not in args:
                raise InvalidOptionValue("-a",
                                         "This option is required when --auth-type is used")
            if args.auth_type == "post" and args.starting_urls != []:
                auth_url = args.starting_urls[0]
            wap.set_auth_type(args.auth_type)

        for bad_param in args.excluded_parameters:
            wap.add_bad_param(bad_param)

        wap.set_max_depth(args.depth)
        wap.set_max_files_per_dir(args.max_files_per_dir)
        wap.set_max_links_per_page(args.max_links_per_page)
        wap.set_scan_force(args.scan_force)
        wap.set_max_scan_time(args.max_scan_time)
        wap.set_max_attack_time(args.max_attack_time)

        # should be a setter
        wap.verbosity(args.verbosity)
        if args.detailed_report:
            wap.set_detail_report()
        if args.color:
            wap.set_color()
        wap.set_timeout(args.timeout)
        wap.set_modules(args.modules)

        if args.no_bugreport:
            wap.set_bug_reporting(False)

        if "user_agent" in args:
            wap.add_custom_header("User-Agent", args.user_agent)

        for custom_header in args.headers:
            if ":" in custom_header:
                hdr_name, hdr_value = custom_header.split(":", 1)
                wap.add_custom_header(hdr_name.strip(), hdr_value.strip())

        wap.set_report_generator_type(args.format)
        wap.set_verify_ssl(bool(args.check_ssl))

        attack_options = {
            "level": args.level,
            "timeout": args.timeout,
            "tasks": args.tasks
        }

        if "dns_endpoint" in args:
            attack_options["dns_endpoint"] = args.dns_endpoint

        if "endpoint" in args:
            endpoint = fix_url_path(args.endpoint)
            if is_valid_endpoint('ENDPOINT', endpoint):
                attack_options["external_endpoint"] = endpoint
                attack_options["internal_endpoint"] = endpoint
            else:
                raise InvalidOptionValue("--endpoint", args.endpoint)

        if "external_endpoint" in args:
            external_endpoint = fix_url_path(args.external_endpoint)
            if is_valid_endpoint('EXTERNAL ENDPOINT', external_endpoint):
                attack_options["external_endpoint"] = external_endpoint
            else:
                raise InvalidOptionValue("--external-endpoint",
                                         external_endpoint)

        if "internal_endpoint" in args:
            internal_endpoint = fix_url_path(args.internal_endpoint)
            if is_valid_endpoint('INTERNAL ENDPOINT', internal_endpoint):
                if ping(internal_endpoint):
                    attack_options["internal_endpoint"] = internal_endpoint
                else:
                    logging.error(
                        _("Error: Internal endpoint URL must "
                          "be accessible from Wapiti!"))
                    raise InvalidOptionValue("--internal-endpoint",
                                             internal_endpoint)
            else:
                raise InvalidOptionValue("--internal-endpoint",
                                         internal_endpoint)

        if args.skipped_parameters:
            attack_options["skipped_parameters"] = set(args.skipped_parameters)

        wap.set_attack_options(attack_options)

        await wap.init_persister()
        await wap.init_crawler()
        if args.flush_attacks:
            await wap.flush_attacks()

        if args.flush_session:
            await wap.flush_session()

    except InvalidOptionValue as msg:
        logging.error(msg)
        sys.exit(2)

    # assert os.path.exists(wap.history_file)

    loop = asyncio.get_event_loop()
    logging.error('start url 1085 ')
    try:
        if not args.skip_crawl:
            logging.error('start url 1088 ')
            if await wap.have_attacks_started() and not args.resume_crawl:
                pass
            else:
                if await wap.has_scan_started():
                    logging.info(
                        _("[*] Resuming scan from previous "
                          "session, please wait"))

                if "auth_type" in args:
                    is_logged_in, form, excluded_urls = \
                        await wap.crawler.async_try_login(
                            auth_credentials,
                            auth_url,
                            args.auth_type
                        )
                    wap.set_auth_state(is_logged_in, form, auth_url,
                                       args.auth_type)
                    for url in excluded_urls:
                        wap.add_excluded_url(url)

                await wap.load_scan_state()
                loop.add_signal_handler(signal.SIGINT,
                                        inner_ctrl_c_signal_handler)
                await wap.browse(global_stop_event, parallelism=args.tasks)
                loop.remove_signal_handler(signal.SIGINT)
                await wap.save_scan_state()

        if args.max_parameters:
            count = await wap.persister.remove_big_requests(
                args.max_parameters)
            # FIXME: Right now we cannot remove the pylint: disable
            #  line because the current I18N system
            # uses the string as a token so we cannot use f string
            # pylint: disable=consider-using-f-string
            logging.info(
                _(f"[*] {count} URLs and forms having more than "
                  f"{args.max_parameters} parameters were removed."))

        logging.info(
            _("[*] Wapiti found "
              f"{await wap.count_resources()} URLs and forms during the scan"))
        loop.add_signal_handler(signal.SIGINT, stop_attack_process)
        await wap.attack(global_stop_event)
        result_atack = await wap.get_result()
        # display result before save it
        logging.error(json.dumps(result_atack))
        loop.remove_signal_handler(signal.SIGINT)

    except OperationalError:
        logging.error(
            _("[!] Can't store information in persister. SQLite database"
              " must have been locked by another process")
        )
        logging.error(_("[!] You should unlock and launch Wapiti again."))
    except SystemExit:
        pass


def wapiti_web_asyncio_wrapper():
    asyncio.run(wapiti_web_main(args=parse_args()))
