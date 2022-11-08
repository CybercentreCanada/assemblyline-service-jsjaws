from base64 import b64decode
from bs4 import BeautifulSoup
from dateutil.parser import parse as dtparse
from hashlib import sha256
from inspect import getmembers, isclass
from json import JSONDecodeError, dumps, load, loads
from os import listdir, mkdir, path
from pkgutil import iter_modules
import re
from requests import get
from subprocess import PIPE, Popen, TimeoutExpired
from sys import modules
import tempfile
from threading import Thread
from time import time
from tinycss2 import parse_stylesheet
from typing import Any, Dict, List, Optional, Set, Tuple

from assemblyline.common.digests import get_sha256_for_file
from assemblyline.common.str_utils import safe_str, truncate
from assemblyline.odm.base import DOMAIN_REGEX, FULL_URI, IP_REGEX, URI_PATH
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.dynamic_service_helper import (
    OntologyResults,
    extract_iocs_from_text_blob,
)
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import (
    Heuristic,
    Result,
    ResultSection,
    ResultTableSection,
    ResultTextSection,
    TableRow,
)

import signatures
from signatures.abstracts import Signature
from tools import tinycss2_helper

# Execution constants
WSCRIPT_SHELL = "wscript.shell"
WSCRIPT_SHELL_REGEX = r"(?i)(?:WScript.Shell\[\d+\]\.Run\()(.*)(?:\))"
MAX_PAYLOAD_FILES_EXTRACTED = 50
RESOURCE_NOT_FOUND_SHA256 = "85658525ce99a2b0887f16b8a88d7acf4ae84649fa05217caf026859721ba04a"
JQUERY_VERSION_REGEX = r"\/\*\!\n \* jQuery JavaScript Library v([\d\.]+)\n"
MAPLACE_REGEX = r"\/\*\*\n\* Maplace\.js\n[\n\r*\sa-zA-Z0-9\(\):\/\.@]+?@version  ([\d\.]+)\n"
COMBO_REGEX = (
    r"\/\*\nCopyright \(c\) 2011 Sencha Inc\. \- Author: Nicolas Garcia Belmonte \(http:\/\/philogb\.github\.com\/\)"
)
MALWARE_JAIL_TIME_STAMP = re.compile(r"\[(.+)\] ")
APPENDCHILD_BASE64_REGEX = re.compile("data:[^;]*;base64,(.*)")

# Signature Constants
TRANSLATED_SCORE = {
    0: 10,  # Informational (0-24% hit rate)
    1: 100,  # On the road to being suspicious (25-34% hit rate)
    2: 250,  # Wow this file could be suspicious (35-44% hit rate)
    3: 500,  # Definitely Suspicious (45-50% hit rate)
    4: 750,  # Highly Suspicious, on the road to being malware (51-94% hit rate)
    5: 1000,  # Malware (95-100% hit rate)
}

# Default cap of 10k lines of stdout from tools
STDOUT_LIMIT = 10000


class JsJaws(ServiceBase):
    def __init__(self, config: Optional[Dict] = None) -> None:
        super(JsJaws, self).__init__(config)
        self.artifact_list: Optional[List[Dict[str, str]]] = None
        self.malware_jail_payload_extraction_dir: Optional[str] = None
        self.malware_jail_sandbox_env_dump: Optional[str] = None
        self.malware_jail_sandbox_env_dir: Optional[str] = None
        self.malware_jail_sandbox_env_dump_path: Optional[str] = None
        self.path_to_jailme_js: Optional[str] = None
        self.path_to_boxjs: Optional[str] = None
        self.path_to_jsxray: Optional[str] = None
        self.boxjs_urls_json_path: Optional[str] = None
        self.malware_jail_urls_json_path: Optional[str] = None
        self.wscript_only_config: Optional[str] = None
        self.extracted_wscript: Optional[str] = None
        self.extracted_wscript_path: Optional[str] = None
        self.malware_jail_output: Optional[str] = None
        self.malware_jail_output_path: Optional[str] = None
        self.extracted_doc_writes: Optional[str] = None
        self.extracted_doc_writes_path: Optional[str] = None
        self.boxjs_output_dir: Optional[str] = None
        self.boxjs_iocs: Optional[str] = None
        self.boxjs_resources: Optional[str] = None
        self.boxjs_analysis_log: Optional[str] = None
        self.boxjs_snippets: Optional[str] = None
        self.filtered_lib: Optional[str] = None
        self.filtered_lib_path: Optional[str] = None
        self.stdout_limit: Optional[int] = None
        self.log.debug("JsJaws service initialized")

    def start(self) -> None:
        self.log.debug("JsJaws service started")
        self.stdout_limit = self.config.get("total_stdout_limit", STDOUT_LIMIT)

    def stop(self) -> None:
        self.log.debug("JsJaws service ended")

    def execute(self, request: ServiceRequest) -> None:
        request.result = Result()
        self.artifact_list = []
        file_path = request.file_path

        with open(file_path, "rb") as fh:
            file_content = fh.read()

        css_path = None
        if request.file_type in ["code/html", "code/hta"]:
            file_path, file_content, css_path = self.extract_using_soup(request, file_content)
        elif request.file_type == "image/svg":
            file_path, file_content, _ = self.extract_using_soup(request, file_content)

        if file_path is None:
            return

        # If the file starts or ends with null bytes, let's strip them out
        if file_content.startswith(b"\x00") or file_content.endswith(b"\x00"):
            with tempfile.NamedTemporaryFile(dir=self.working_directory, delete=False, mode="wb") as f:
                file_content = file_content[:].strip(b"\x00")
                f.write(file_content)
                file_path = f.name

        # File constants
        self.malware_jail_payload_extraction_dir = path.join(self.working_directory, "payload/")
        self.malware_jail_sandbox_env_dump = "sandbox_dump.json"
        self.malware_jail_sandbox_env_dir = path.join(self.working_directory, "sandbox_env")
        self.malware_jail_sandbox_env_dump_path = path.join(
            self.malware_jail_sandbox_env_dir, self.malware_jail_sandbox_env_dump
        )
        root_dir = path.dirname(path.abspath(__file__))
        self.path_to_jailme_js = path.join(root_dir, "tools/jailme.cjs")
        self.path_to_boxjs = path.join(root_dir, "tools/node_modules/box-js/run.js")
        self.path_to_jsxray = path.join(root_dir, "tools/js-x-ray-run.js")
        self.malware_jail_urls_json_path = path.join(self.malware_jail_payload_extraction_dir, "urls.json")
        self.wscript_only_config = path.join(root_dir, "tools/config_wscript_only.json")
        self.extracted_wscript = "extracted_wscript.bat"
        self.extracted_wscript_path = path.join(self.malware_jail_payload_extraction_dir, self.extracted_wscript)
        self.malware_jail_output = "output.txt"
        self.malware_jail_output_path = path.join(self.working_directory, self.malware_jail_output)
        self.extracted_doc_writes = "document_writes.html"
        self.extracted_doc_writes_path = path.join(self.malware_jail_payload_extraction_dir, self.extracted_doc_writes)
        self.boxjs_output_dir = path.join(self.working_directory, f"{request.sha256}.results")
        self.boxjs_urls_json_path = path.join(self.boxjs_output_dir, "urls.json")
        self.boxjs_iocs = path.join(self.boxjs_output_dir, "IOC.json")
        self.boxjs_resources = path.join(self.boxjs_output_dir, "resources.json")
        self.boxjs_analysis_log = path.join(self.boxjs_output_dir, "analysis.log")
        self.boxjs_snippets = path.join(self.boxjs_output_dir, "snippets.json")
        self.filtered_lib = "filtered_lib.js"
        self.filtered_lib_path = path.join(self.working_directory, self.filtered_lib)

        # Setup directory structure
        if not path.exists(self.malware_jail_payload_extraction_dir):
            mkdir(self.malware_jail_payload_extraction_dir)

        if not path.exists(self.malware_jail_sandbox_env_dir):
            mkdir(self.malware_jail_sandbox_env_dir)

        # Grabbing service level configuration variables and submission variables
        download_payload = request.get_param("download_payload")
        allow_download_from_internet = self.config.get("allow_download_from_internet", False)
        tool_timeout = request.get_param("tool_timeout")
        browser_selected = request.get_param("browser")
        log_errors = request.get_param("log_errors")
        wscript_only = request.get_param("wscript_only")
        throw_http_exc = request.get_param("throw_http_exc")
        extract_function_calls = request.get_param("extract_function_calls")
        extract_eval_calls = request.get_param("extract_eval_calls")
        add_supplementary = request.get_param("add_supplementary")
        static_signatures = request.get_param("static_signatures")
        no_shell_error = request.get_param("no_shell_error")
        display_iocs = request.get_param("display_iocs")

        # --loglevel             Logging level (debug, verbose, info, warning, error - default "info")
        # --no-kill              Do not kill the application when runtime errors occur
        # --output-dir           The location on disk to write the results files and folders to (defaults to the
        #                        current directory)
        boxjs_args = [self.path_to_boxjs, "--loglevel", "debug", "--no-kill", "--output-dir", self.working_directory]

        # -s odir  ... output directory for generated files (malware payload)
        # -o ofile ... name of the file where sandbox shall be dumped at the end
        # -b id    ... browser type, use -b list for possible values (Possible -b values:
        # [ 'IE11_W10', 'IE8', 'IE7', 'iPhone', 'Firefox', 'Chrome' ])
        # -t msecs - limits execution time by "msecs" milliseconds, by default 60 seconds.
        malware_jail_args = [
            "node",
            self.path_to_jailme_js,
            "-s",
            self.malware_jail_payload_extraction_dir,
            "-o",
            self.malware_jail_sandbox_env_dump_path,
            "-b",
            browser_selected,
            "-t",
            f"{tool_timeout * 1000}",
        ]

        # If a CSS file path was extracted from the HTML/HTA, pass it to MalwareJail
        if css_path:
            malware_jail_args.append(f"--stylesheet={css_path}")

        # If the Assemblyline environment is allowing service containers to reach the Internet,
        # then allow_download_from_internet service variable needs to be set to true

        # If the user has requested the sample to download any payload from the Internet, and
        # the service is allowed to reach the Internet, then add the following flag
        if allow_download_from_internet and download_payload:
            # --down   ... allow downloading malware payloads from remote servers
            malware_jail_args.append("--down=y")
            # --download             Actually download the payloads
            boxjs_args.append("--download")
        # If the user has requested the sample to download any payload from the Internet, and
        # the service is NOT allowed to reach the Internet, then add a ResultSection letting
        # them know and simulate all network call responses with a 404 Not Found
        elif not allow_download_from_internet and download_payload:
            request.result.add_section(ResultSection("Internet Access is disabled."))
            # --h404   ... on download return always HTTP/404
            malware_jail_args.append("--h404")
        # By selecting the throw_http_exc flag, the sandbox will throw an error in every
        # network call. This is useful for attempting different code execution paths.
        elif throw_http_exc:
            malware_jail_args.append("--t404")
        # As a default, the sandbox will simulate all network call responses with a 404 Not Found
        else:
            # --h404   ... on download return always HTTP/404
            malware_jail_args.append("--h404")

        # --no-shell-error       Do not throw a fake error when executing `WScriptShell.Run` (it throws a fake
        #                        error by default to pretend that the distribution sites are down, so that the
        #                        script will attempt to poll every site)
        if no_shell_error:
            boxjs_args.append("--no-shell-error")

        # Files that each represent a Function Call can be noisy and not particularly useful
        # This flag turns on this extraction
        if request.deep_scan or extract_function_calls:
            malware_jail_args.append("--extractfns")

        # Files that each represent a Eval Call can be noisy and not particularly useful
        # This flag turns on this extraction
        if request.deep_scan or extract_eval_calls:
            malware_jail_args.append("--extractevals")

        # By default, detonation takes place within a sandboxed browser. This option allows
        # for the sample to be run in WScript only
        if wscript_only:
            malware_jail_args.extend(["-c", self.wscript_only_config])

        # By default, we don't want to replace exception catching in a script with a log of the exception,
        # but it is useful for debugging
        if log_errors:
            malware_jail_args.append("--logerrors")

        jsxray_args = ["node", self.path_to_jsxray]

        # Don't forget the sample!
        boxjs_args.append(file_path)
        malware_jail_args.append(file_path)
        jsxray_args.append(file_path)

        tool_threads: List[Thread] = []
        responses: Dict[str, List[str]] = {}
        tool_threads.append(Thread(target=self._run_tool, args=("Box.js", boxjs_args, responses)))
        tool_threads.append(Thread(target=self._run_tool, args=("MalwareJail", malware_jail_args, responses)))
        tool_threads.append(Thread(target=self._run_tool, args=("JS-X-Ray", jsxray_args, responses)))

        for thr in tool_threads:
            thr.start()

        for thr in tool_threads:
            thr.join(timeout=tool_timeout)

        boxjs_output: List[str] = []
        if path.exists(self.boxjs_analysis_log):
            with open(self.boxjs_analysis_log, "r") as f:
                boxjs_output = f.readlines()

        malware_jail_output = responses.get("MalwareJail", [])
        jsxray_output: Dict[Any] = {}
        try:
            if len(responses.get("JS-X-Ray", [])) > 0:
                jsxray_output = loads(responses["JS-X-Ray"][0])
        except JSONDecodeError:
            pass

        # ==================================================================
        # Magic Section
        # ==================================================================

        # We are running signatures based on the output observed from dynamic execution
        # (boxjs_output and malware_jail_output)
        # as well as the file contents themselves (static analysis)
        if static_signatures:
            static_file_lines = []
            for line in safe_str(file_content).split("\n"):
                if ";" in line:
                    static_file_lines.extend(line.split(";"))
                else:
                    static_file_lines.append(line)
            total_output = (
                boxjs_output[: self.stdout_limit] + malware_jail_output[: self.stdout_limit] + static_file_lines
            )
        else:
            total_output = boxjs_output[: self.stdout_limit] + malware_jail_output[: self.stdout_limit]

        total_output = total_output[: self.stdout_limit]
        self._run_signatures(total_output, request.result, display_iocs)

        self._extract_boxjs_iocs(request.result)
        self._extract_malware_jail_iocs(malware_jail_output, request)
        self._extract_wscript(total_output, request.result)
        self._extract_doc_writes(malware_jail_output)
        self._extract_payloads(request.sha256, request.deep_scan)
        self._extract_urls(request.result)
        try:
            self._extract_filtered_code(request.result, file_content.decode())
        except UnicodeDecodeError:
            pass
        if add_supplementary:
            self._extract_supplementary(malware_jail_output)
        self._flag_jsxray_iocs(jsxray_output, request.result)

        # Adding sandbox artifacts using the OntologyResults helper class
        _ = OntologyResults.handle_artifacts(self.artifact_list, request)

    def append_content(self, content: str, file_content: bytes, aggregated_script: Optional[tempfile.NamedTemporaryFile]) -> Tuple[bytes, tempfile.NamedTemporaryFile]:
        """
        This method appends contents to a NamedTemporaryFile
        :param content: content to be appended
        :param file_content: The file content of the NamedTemporaryFile
        :param aggregated_script: The NamedTemporaryFile object
        :return: A tuple of the file contents of the NamedTemporaryFile object and the NamedTemporaryFile object
        """
        encoded_script = content.encode()
        if aggregated_script is None:
            aggregated_script = tempfile.NamedTemporaryFile(dir=self.working_directory, delete=False, mode="wb")
        file_content += encoded_script + b"\n"
        aggregated_script.write(encoded_script + b"\n")
        return file_content, aggregated_script

    def extract_using_soup(self, request: ServiceRequest, file_content: bytes) -> Tuple[str, bytes, Optional[str]]:
        """
        This method extracts elements from an HTML file using the BeautifulSoup library
        :param request: The ServiceRequest object
        :param file_content: The contents of the file to be read
        :return: A tuple of the JavaScript file name that was written, the contents of the file that was written, and the name of the CSS file that was written
        """
        soup = BeautifulSoup(file_content, features="html5lib")
        scripts = soup.findAll("script")
        aggregated_js_script = None
        js_content = b""
        for script in scripts:
            # Make sure there is actually a body to the script
            body = script.string
            if body is None:
                continue
            body = str(body).strip()  # Remove whitespace
            if len(body) <= 2:  # We can treat 2 character scripts as empty
                continue

            if script.get("type", "").lower() in ["", "text/javascript"]:
                # If there is no "type" attribute specified in a script element, then the default assumption is
                # that the body of the element is Javascript
                js_content, aggregated_js_script = self.append_content(body, js_content, aggregated_js_script)

        for line in soup.body.get_attribute_list("onpageshow"):
            if line:
                js_content, aggregated_js_script = self.append_content(line, js_content, aggregated_js_script)

        if aggregated_js_script is None:
            return None, js_content, None

        onloads = soup.body.get_attribute_list("onload")
        for onload in onloads:
            if onload:
                js_content, aggregated_js_script = self.append_content(onload, js_content, aggregated_js_script)

        aggregated_js_script.close()

        request.add_supplementary(aggregated_js_script.name, "temp_javascript.js", "Extracted javascript")

        # Payloads can be hidden in the CSS, so we should try to extract these values and pass them to our JavaScript analysis envs
        styles = soup.findAll("style")
        style_json = dict()
        css_content = b""
        aggregated_css_script = None
        for style in styles:
            # Make sure there is actually a body to the script
            body = style.string
            if body is None:
                continue
            body = str(body).strip()  # Remove whitespace

            css_content, aggregated_css_script = self.append_content(body, css_content, aggregated_css_script)

            # Parse CSS to JSON
            qualified_rules = parse_stylesheet(body, skip_comments=True, skip_whitespace=True)
            for qualified_rule in qualified_rules:
                preludes = tinycss2_helper.significant_tokens(qualified_rule.prelude)
                if len(preludes) > 1:
                    prelude_name = ''.join([prelude.value for prelude in preludes])
                    self.log.debug(f"Combine all preludes to get the declaration name: {[prelude.value for prelude in preludes]} -> {prelude_name}")
                else:
                    prelude_name = preludes[0].value
                output = tinycss2_helper.parse_declaration_list(qualified_rule.content, skip_comments=True, skip_whitespace=True)
                style_json[prelude_name] = output

        if aggregated_css_script is None:
            return aggregated_js_script.name, js_content, None

        aggregated_css_script.close()

        if style_json:
            request.add_supplementary(aggregated_css_script.name, "temp_css.css", "Extracted CSS")
            css_script_name = aggregated_css_script.name

            # Look for suspicious CSS usage
            for _, rules in style_json.items():
                for rule in rules:
                    declaration_blocks = rule.values()
                    for declaration_block in declaration_blocks:
                        for item in declaration_block.get("values", []):
                            if isinstance(item, dict):
                                if item.get("url"):
                                    # SUS
                                    url_path = None
                                    # If the content is base64 encoded, decode it before we extract it
                                    matches = re.match(APPENDCHILD_BASE64_REGEX, item["url"])
                                    if len(matches.regs) == 2:
                                        item["url"] = b64decode(matches.group(1).encode())
                                    else:
                                        item["url"] = item["url"].encode()
                                    with tempfile.NamedTemporaryFile(dir=self.working_directory, delete=False, mode="wb") as t:
                                        t.write(item["url"])
                                        url_path = t.name
                                    request.add_extracted(url_path, get_sha256_for_file(url_path), "URL value from CSS")
                                    heur = Heuristic(7)
                                    _ = ResultTextSection(heur.name, heuristic=heur, parent=request.result, body=heur.description)
        else:
            css_script_name = None

        return aggregated_js_script.name, file_content, css_script_name

    def _extract_wscript(self, output: List[str], result: Result) -> None:
        """
        This method does a couple of things:
        1. It looks for lines from the output that contain shell scripts, and writes these to a file for extraction
        2. It attempts to extract IOCs from these shell scripts
        :param output: A list of strings where each string is a line of stdout from the MalwareJail tool
        :param result: A Result object containing the service results
        :return: None
        """
        wscript_extraction = open(self.extracted_wscript_path, "a+")
        wscript_res_sec = ResultTableSection("IOCs extracted from WScript")
        for line in output:
            wscript_shell_run = re.search(re.compile(WSCRIPT_SHELL_REGEX), line)
            # Script was run
            if wscript_shell_run:
                cmd = wscript_shell_run.group(1)
                # This is a byproduct of the sandbox using WScript.Shell.Run
                for item in [", 0, undefined", ", 1, 0", ", 0, false"]:
                    if item in cmd:
                        cmd = cmd.replace(item, "")
                # Write command to file
                wscript_extraction.write(cmd + "\n")
                # Let's try to extract IOCs from it
                extract_iocs_from_text_blob(line, wscript_res_sec)
        wscript_extraction.close()

        if path.getsize(self.extracted_wscript_path) > 0:
            artifact = {
                "name": self.extracted_wscript,
                "path": self.extracted_wscript_path,
                "description": "Extracted WScript",
                "to_be_extracted": True,
            }
            self.log.debug(f"Adding extracted file: {self.extracted_wscript}")
            self.artifact_list.append(artifact)
            if wscript_res_sec.body:
                result.add_section(wscript_res_sec)

    def _extract_payloads(self, sample_sha256: str, deep_scan: bool) -> None:
        """
        This method extracts unique payloads that were written to disk by MalwareJail and Box.js
        :param sample_sha256: The SHA256 of the submitted file
        :param deep_scan: A boolean representing if the user has requested a deep scan
        :return: None
        """
        unique_shas = {sample_sha256}
        max_payloads_extracted = self.config.get("max_payloads_extracted", MAX_PAYLOAD_FILES_EXTRACTED)
        extracted_count = 0

        malware_jail_payloads = [
            (file, path.join(self.malware_jail_payload_extraction_dir, file))
            for file in sorted(listdir(self.malware_jail_payload_extraction_dir))
        ]

        # These are dumped files from Box.js of js that was run successfully
        files_to_not_extract = set()
        if path.exists(self.boxjs_snippets):
            with open(self.boxjs_snippets, "r") as f:
                snippets = loads(f.read())
                for snippet in snippets:
                    files_to_not_extract.add(snippet)

        box_js_payloads = []
        if path.exists(self.boxjs_output_dir):
            box_js_payloads = [
                (file, path.join(self.boxjs_output_dir, file))
                for file in sorted(listdir(self.boxjs_output_dir))
                if file not in files_to_not_extract
            ]

        all_payloads = malware_jail_payloads + box_js_payloads

        for file, extracted in all_payloads:
            # No empty files
            if path.getsize(extracted) == 0:
                continue
            # These are not payloads
            if extracted in [
                self.malware_jail_urls_json_path,
                self.extracted_wscript_path,
                self.extracted_doc_writes_path,
                self.boxjs_iocs,
                self.boxjs_resources,
                self.boxjs_snippets,
                self.boxjs_analysis_log,
                self.boxjs_urls_json_path,
            ]:
                continue
            extracted_sha = get_sha256_for_file(extracted)
            if extracted_sha not in unique_shas and extracted_sha not in [RESOURCE_NOT_FOUND_SHA256]:
                extracted_count += 1
                if not deep_scan and extracted_count > max_payloads_extracted:
                    self.log.debug(f"The maximum number of payloads {max_payloads_extracted} were extracted.")
                    return
                unique_shas.add(extracted_sha)
                artifact = {
                    "name": safe_str(file),
                    "path": extracted,
                    "description": "Extracted Payload",
                    "to_be_extracted": True,
                }
                self.log.debug(f"Adding extracted file: {safe_str(file)}")
                self.artifact_list.append(artifact)

    def _parse_malwarejail_output(self, output: List[str]) -> str:
        """
        This method is a generator that validates whether a new line of malwarejail output exists
        :param output: All malwarejail output
        :return: None
        """
        # ret represents the value to be yielded
        ret = None
        for line in output:
            if "] " in line:
                try:
                    timestamp = re.match(MALWARE_JAIL_TIME_STAMP, line)
                    if not timestamp:
                        continue
                    if len(timestamp.regs) < 2:
                        continue
                    dtparse(timestamp.group(1))
                    if ret is not None:
                        yield ret
                    # We have a valid timestamp match but nothing to yield
                    ret = ""
                except ValueError:
                    pass
            if ret:
                ret = f"{ret}\n"
            if not ret:
                ret = f"{line}"
                continue
            ret = f"{ret}{line}"
        if ret is not None:
            yield ret

    def _extract_doc_writes(self, output: List[str]) -> None:
        """
        This method writes all document writes to a file and adds that in an extracted file
        :param output: A list of strings where each string is a line of stdout from the MalwareJail tool
        :param result: A Result object containing the service results
        """
        extracted_doc_writes = open(self.extracted_doc_writes_path, "a+")
        doc_write = False
        for line in self._parse_malwarejail_output(output):
            if doc_write:
                extracted_doc_writes.write(line.split("] => '", 1)[1][:-1] + "\n")
                doc_write = False
            if all(item in line.split("] ", 1)[1][:40] for item in ["document", "write(content)"]):
                doc_write = True

        extracted_doc_writes.close()

        if path.getsize(self.extracted_doc_writes_path) > 0:
            self.artifact_list.append(
                {
                    "name": self.extracted_doc_writes,
                    "path": self.extracted_doc_writes_path,
                    "description": "DOM Writes",
                    "to_be_extracted": True,
                }
            )
            self.log.debug(f"Adding extracted file: {self.extracted_doc_writes}")

    def _extract_urls(self, result: Result) -> None:
        """
        This method extracts the URL interactions from urls.json that is dumped by MalwareJail
        This method also extracts the URL interactions from the IOC.json that is dumped by Box.js
        :param result: A Result object containing the service results
        :return: None
        """
        if not path.exists(self.malware_jail_urls_json_path) and not path.exists(self.boxjs_iocs):
            return

        urls_result_section = ResultTableSection("URLs")

        urls_rows: List[TableRow] = []
        items_seen: Set[str] = set()

        if path.exists(self.malware_jail_urls_json_path):
            with open(self.malware_jail_urls_json_path, "r") as f:
                file_contents = f.read()
                urls_json = loads(file_contents)
                for item in urls_json:
                    if dumps(item) not in items_seen:
                        items_seen.add(dumps(item))
                        urls_rows.append(TableRow(**item))
                    else:
                        continue
                for url in urls_rows:
                    self._tag_uri(url["url"], urls_result_section)

        if path.exists(self.boxjs_iocs):
            with open(self.boxjs_iocs, "r") as f:
                file_contents = f.read()
                ioc_json = loads(file_contents)
                for ioc in ioc_json:
                    value = ioc["value"]
                    if ioc["type"] == "UrlFetch":
                        if any(value["url"] == url["url"] for url in urls_rows):
                            continue
                        item = {"url": value["url"], "method": value["method"], "request_headers": value["headers"]}
                        if dumps(item) not in items_seen:
                            items_seen.add(dumps(item))
                            urls_rows.append(TableRow(**item))
                        else:
                            continue
                        self._tag_uri(value["url"], urls_result_section)

        if urls_rows:
            [urls_result_section.add_row(urls_row) for urls_row in urls_rows]
            urls_result_section.set_heuristic(1)
            result.add_section(urls_result_section)

    def _extract_supplementary(self, output: List[str]) -> None:
        """
        This method adds the sandbox environment dump and the MalwareJail stdout as supplementary files, as well as
        the dumps from Box.js
        :param output: A list of strings where each string is a line of stdout from the MalwareJail tool
        :return: None
        """
        if path.exists(self.malware_jail_sandbox_env_dump_path):
            # Get the sandbox env json that is dumped. This should always exist.
            malware_jail_sandbox_env_dump = {
                "name": self.malware_jail_sandbox_env_dump,
                "path": self.malware_jail_sandbox_env_dump_path,
                "description": "Sandbox Environment Details",
                "to_be_extracted": False,
            }
            self.log.debug(f"Adding supplementary file: {self.malware_jail_sandbox_env_dump}")
            self.artifact_list.append(malware_jail_sandbox_env_dump)

        if output:
            with open(self.malware_jail_output_path, "w") as f:
                for line in output:
                    f.write(line + "\n")
            mlwr_jail_out = {
                "name": self.malware_jail_output,
                "path": self.malware_jail_output_path,
                "description": "Malware Jail Output",
                "to_be_extracted": False,
            }
            self.log.debug(f"Adding supplementary file: {self.malware_jail_output}")
            self.artifact_list.append(mlwr_jail_out)

        if path.exists(self.boxjs_analysis_log):
            boxjs_analysis_log = {
                "name": "boxjs_analysis_log.log",
                "path": self.boxjs_analysis_log,
                "description": "Box.js Output",
                "to_be_extracted": False,
            }
            self.log.debug(f"Adding supplementary file: {self.boxjs_analysis_log}")
            self.artifact_list.append(boxjs_analysis_log)

    def _run_signatures(self, output: List[str], result: Result, display_iocs: bool = False) -> None:
        """
        This method sets up the parallelized signature engine and runs each signature against the
        stdout from MalwareJail
        :param output: A list of strings where each string is a line of stdout from the MalwareJail tool
        :param result: A Result object containing the service results
        :param display_iocs: A boolean indicating if we are going to include the signature marks in the
        ResultSection
        :return: None
        """
        # Loading signatures
        sigs = []
        abstracts = "signatures.abstracts"
        signature_class = "Signature"
        for _, modname, _ in iter_modules(signatures.__path__, f"{signatures.__name__}."):
            if modname == abstracts:
                continue
            __import__(modname)
            clsmembers = getmembers(modules[modname], isclass)
            for cls in clsmembers:
                name, obj = cls
                if name == signature_class:
                    continue
                sigs.append(obj())

        # Running signatures
        signatures_that_hit = []
        sig_threads = []

        self.log.debug(f"Running {len(sigs)} signatures...")
        start_time = time()
        for sig in sigs:
            thr = Thread(target=self._process_signature, args=(sig, output, signatures_that_hit))
            sig_threads.append(thr)
            thr.start()

        for thread in sig_threads:
            thread.join()
        self.log.debug(f"Completed running {len(sigs)} signatures! Time elapsed: {round(time() - start_time)}s")

        # Adding signatures to results
        if len(signatures_that_hit) > 0:
            sigs_res_sec = ResultSection("Signatures")
            for sig_that_hit in signatures_that_hit:
                sig_res_sec = ResultTextSection(f"Signature: {type(sig_that_hit).__name__}", parent=sigs_res_sec)
                sig_res_sec.add_line(sig_that_hit.description)
                sig_res_sec.set_heuristic(sig_that_hit.heuristic_id)
                translated_score = TRANSLATED_SCORE[sig_that_hit.severity]
                sig_res_sec.heuristic.add_signature_id(sig_that_hit.name, score=translated_score)
                if display_iocs:
                    for mark in sig_that_hit.marks:
                        sig_res_sec.add_line(f"\t\t{truncate(mark)}")

            result.add_section(sigs_res_sec)

    @staticmethod
    def _process_signature(signature: Signature, output: List[str], signatures_that_hit: List[Signature]) -> None:
        """
        This method is used for the purpose of multi-threading and sharing the signatures_that_hit list
        :param signature: A Signature object that represents a signature
        :param output: A list of strings where each string is a line of stdout from the MalwareJail tool
        :param signatures_that_hit: A list containing all signatures that hit
        :return: None
        """
        signature.process_output(output)
        if len(signature.marks) > 0:
            signatures_that_hit.append(signature)

    def _extract_boxjs_iocs(self, result: Result) -> None:
        """
        This method extracts IOCs that Box.js has reported
        :param result: A Result object containing the service results
        :return: None
        """
        if path.exists(self.boxjs_iocs):
            ioc_result_section = ResultSection("IOCs extracted by Box.js")
            with open(self.boxjs_iocs, "r") as f:
                file_contents = f.read()
                ioc_json = loads(file_contents)
            commands = set()
            file_writes = set()
            file_reads = set()
            cmd_count = 0
            for ioc in ioc_json:
                type = ioc["type"]
                value = ioc["value"]
                if type == "Run" and "command" in value:
                    commands.add(value["command"])
                    cmd_file_name = f"cmd_{cmd_count}.txt"
                    cmd_file_path = path.join(self.working_directory, cmd_file_name)
                    with open(cmd_file_path, "w") as f:
                        f.write(value["command"])
                    self.artifact_list.append(
                        {
                            "name": cmd_file_name,
                            "path": cmd_file_path,
                            "description": "Command Extracted",
                            "to_be_extracted": True,
                        }
                    )
                    self.log.debug(f"Adding extracted file: {cmd_file_name}")
                    cmd_count += 1
                elif type == "FileWrite" and "file" in value:
                    file_writes.add(value["file"])
                elif type == "FileRead" and "file" in value:
                    file_reads.add(value["file"])
            if commands:
                cmd_result_section = ResultTextSection(
                    "The script ran the following commands", parent=ioc_result_section
                )
                cmd_result_section.add_lines(list(commands))
                [cmd_result_section.add_tag("dynamic.process.command_line", command) for command in list(commands)]
                cmd_iocs_result_section = ResultTableSection("IOCs found in command lines")
                extract_iocs_from_text_blob(cmd_result_section.body, cmd_iocs_result_section)
                if cmd_iocs_result_section.body:
                    cmd_iocs_result_section.set_heuristic(2)
                    cmd_result_section.add_subsection(cmd_iocs_result_section)
            if file_writes:
                file_writes_result_section = ResultTextSection(
                    "The script wrote the following files", parent=ioc_result_section
                )
                file_writes_result_section.add_lines(list(file_writes))
                [
                    file_writes_result_section.add_tag("dynamic.process.file_name", file_write)
                    for file_write in list(file_writes)
                ]
            if file_reads:
                file_reads_result_section = ResultTextSection(
                    "The script read the following files", parent=ioc_result_section
                )
                file_reads_result_section.add_lines(list(file_reads))
                [
                    file_reads_result_section.add_tag("dynamic.process.file_name", file_read)
                    for file_read in list(file_reads)
                ]

            if ioc_result_section.subsections:
                ioc_result_section.set_heuristic(2)
                result.add_section(ioc_result_section)

    def _tag_uri(self, url: str, urls_result_section: ResultTableSection) -> None:
        """
        This method tags components of a URI
        :param url: The url to be analyzed
        :param urls_result_section: The result section which will have the tags of the uri components added to it
        :return: None
        """
        safe_url = safe_str(url)
        # Extract URI
        uri_match = re.match(FULL_URI, safe_url)
        if uri_match:
            urls_result_section.add_tag("network.dynamic.uri", safe_url)
            # Extract domain
            domain_match = re.search(DOMAIN_REGEX, safe_url)
            if domain_match:
                domain = domain_match.group(0)
                urls_result_section.add_tag("network.dynamic.domain", domain)
            # Extract IP
            ip_match = re.search(IP_REGEX, safe_url)
            if ip_match:
                ip = ip_match.group(0)
                urls_result_section.add_tag("network.dynamic.ip", ip)
            # Extract URI path
            if "//" in safe_url:
                safe_url = safe_url.split("//")[1]
            uri_path_match = re.search(URI_PATH, safe_url)
            if uri_path_match:
                uri_path = uri_path_match.group(0)
                urls_result_section.add_tag("network.dynamic.uri_path", uri_path)
        else:
            # Might as well tag this while we're here
            urls_result_section.add_tag("file.string.extracted", safe_url)

    @staticmethod
    def _flag_jsxray_iocs(output: Dict[str, Any], result: Result) -> None:
        """
        This method flags anything noteworthy from the Js-X-Ray output
        :param output: The output from JS-X-Ray
        :param result: A Result object containing the service results
        :return: None
        """
        jsxray_iocs_result_section = ResultTextSection("JS-X-Ray IOCs Detected")
        warnings: List[Dict[str, Any]] = output.get("warnings", [])
        for warning in warnings:
            kind = warning["kind"]
            val = warning.get("value")
            if kind == "unsafe-stmt":
                jsxray_iocs_result_section.add_line(f"\t\tAn unsafe statement was found: {truncate(safe_str(val))}")
            elif kind == "encoded-literal":
                jsxray_iocs_result_section.add_line(f"\t\tAn encoded literal was found: {truncate(safe_str(val))}")
                jsxray_iocs_result_section.add_tag("file.string.extracted", safe_str(val))
            elif kind == "obfuscated-code":
                jsxray_iocs_result_section.add_line(
                    f"\t\tObfuscated code was found that was obfuscated by: " f"{safe_str(val)}"
                )
        if jsxray_iocs_result_section.body and len(jsxray_iocs_result_section.body) > 0:
            jsxray_iocs_result_section.set_heuristic(2)
            result.add_section(jsxray_iocs_result_section)

    def parse_msdt_powershell(self, cmd):
        import shlex

        ori_parts = shlex.split(cmd)
        parts = shlex.split(cmd.lower())

        if "/param" in parts:
            param = ori_parts[parts.index("/param") + 1]
        elif "-param" in parts:
            param = ori_parts[parts.index("-param") + 1]
        else:
            return cmd

        for element in param.split():
            if element.startswith("IT_BrowseForFile="):
                return element[17:]
        return cmd

    def _extract_malware_jail_iocs(self, output: List[str], request: ServiceRequest) -> None:
        malware_jail_res_sec = ResultTableSection("MalwareJail extracted the following IOCs")
        for line in self._parse_malwarejail_output(output):
            split_line = line.split("] ", 1)
            if len(split_line) == 2:
                log_line = split_line[1]
            else:
                log_line = line
            if len(log_line) > 10000:
                log_line = truncate(log_line, 10000)
            extract_iocs_from_text_blob(log_line, malware_jail_res_sec)

            if log_line.startswith("Exception occurred in "):
                exception_lines = []
                for exception_line in log_line.split("\n")[::-1]:
                    if not exception_line.strip():
                        break
                    exception_lines.append(exception_line)
                if not exception_lines:
                    continue
                if self.config.get("raise_malware_jail_exc", False):
                    raise Exception("Exception occurred in MalwareJail\n" + "\n".join(exception_lines[::-1]))
                else:
                    self.log.warning("Exception occurred in MalwareJail\n" + "\n".join(exception_lines[::-1]))
            if log_line.startswith("location.href = "):
                # We need to recover the non-truncated content from the sandbox_dump.json file
                with open(self.malware_jail_sandbox_env_dump_path, "r") as f:
                    data = load(f)
                    location_href = data["location"]["_props"]["href"]
                    if location_href.lower().startswith("ms-msdt:"):
                        heur = Heuristic(5)
                        res = ResultTextSection(heur.name, heuristic=heur, parent=request.result)

                        # Try to only recover the msdt command's powershell for the extracted file
                        # If we can't, write the whole command
                        try:
                            encoded_content = self.parse_msdt_powershell(location_href).encode()
                        except ValueError:
                            encoded_content = location_href.encode()

                        with tempfile.NamedTemporaryFile(dir=self.working_directory, delete=False) as out:
                            out.write(encoded_content)
                        request.add_extracted(
                            out.name, sha256(encoded_content).hexdigest(), "Redirection location"
                        )
                    else:
                        heur = Heuristic(6)
                        res = ResultTextSection(heur.name, heuristic=heur, parent=request.result)
                        res.add_tag("network.static.uri", location_href)
                    res.add_line("Redirection to:")
                    res.add_line(location_href)

        if malware_jail_res_sec.body:
            malware_jail_res_sec.set_heuristic(2)
            request.result.add_section(malware_jail_res_sec)

    def _run_tool(
        self,
        tool_name: str,
        args: List[str],
        resp: Dict[str, Any],
    ) -> None:
        self.log.debug(f"Running {tool_name}...")
        start_time = time()
        resp[tool_name] = []
        try:
            # Stream stdout to resp rather than waiting for process to finish
            with Popen(args=args, stdout=PIPE, bufsize=1, universal_newlines=True) as p:
                for line in p.stdout:
                    resp[tool_name].append(line)
        except TimeoutExpired:
            pass
        except Exception as e:
            self.log.warning(f"{tool_name} crashed due to {repr(e)}")
        self.log.debug(f"Completed running {tool_name}! Time elapsed: {round(time() - start_time)}s")

    def _extract_filtered_code(self, result: Result, file_contents: str):
        common_libs = {
            # URL/FILE: REGEX
            "https://code.jquery.com/jquery-%s.js": JQUERY_VERSION_REGEX,
            "clean_libs/maplace%s.js": MAPLACE_REGEX,
            "clean_libs/combo.js": COMBO_REGEX,
        }
        file_contents = file_contents.replace("\r", "")
        split_file_contents = [line.strip() for line in file_contents.split("\n") if line.strip()]
        for lib_path, regex in common_libs.items():
            regex_match = re.match(regex, file_contents)
            if not regex_match:
                continue
            if lib_path.startswith("https"):
                if not self.service_attributes.docker_config.allow_internet_access:
                    continue
                if len(regex_match.regs) > 1:
                    resp = get(lib_path % regex_match.group(1), timeout=15)
                else:
                    resp = get(lib_path, timeout=15)

                path_contents = resp.text
            else:
                if len(regex_match.regs) > 1:
                    path_contents = open(lib_path % regex_match.group(1), "r").read()
                else:
                    path_contents = open(lib_path, "r").read()

            diff = list()
            clean_file_contents = [line.strip() for line in path_contents.split("\n") if line.strip()]
            # The dirty file contents should always have more lines than the clean file contents
            dirty_file_line_offset = 0
            for index, item in enumerate(clean_file_contents):
                dirty_file_line_index = index + dirty_file_line_offset

                if dirty_file_line_index >= len(split_file_contents):
                    break

                dirty_file_line_to_compare = split_file_contents[dirty_file_line_index]
                if self._compare_lines(item, dirty_file_line_to_compare):
                    pass
                else:
                    while not self._compare_lines(item, dirty_file_line_to_compare):
                        diff.append(dirty_file_line_to_compare)
                        dirty_file_line_offset += 1
                        dirty_file_line_index = index + dirty_file_line_offset

                        if dirty_file_line_index >= len(split_file_contents):
                            break

                        dirty_file_line_to_compare = split_file_contents[dirty_file_line_index]

            if len(diff) > 0:
                embedded_code_in_lib_res_sec = ResultTextSection("Embedded code was found in common library")
                embedded_code_in_lib_res_sec.add_line(f"View extracted file {self.filtered_lib} for details.")
                embedded_code_in_lib_res_sec.set_heuristic(4)
                result.add_section(embedded_code_in_lib_res_sec)
                with open(self.filtered_lib_path, "w") as f:
                    for line in diff:
                        f.write(f"{line}\n")
                artifact = {
                    "name": self.filtered_lib,
                    "path": self.filtered_lib_path,
                    "description": "JavaScript embedded within common library",
                    "to_be_extracted": True,
                }
                self.log.debug(f"Adding extracted file: {self.filtered_lib}")
                self.artifact_list.append(artifact)

    @staticmethod
    def _compare_lines(line_1: str, line_2: str) -> bool:
        """
        This method compares two lines and returns their equivalence
        :param line_1: The first line to compare
        :param line_2: The second line to compare
        :return: A boolean representing that the lines are equivalent
        """
        if line_1.startswith("//"):
            line_1 = line_1[2:]

        if line_2.startswith("//"):
            line_2 = line_2[2:]

        line_1 = line_1.strip()
        line_2 = line_2.strip()

        return line_1 == line_2
