from hashlib import sha256
from inspect import getmembers, isclass
from json import loads, dumps, JSONDecodeError
from os import mkdir, listdir, path
from pkgutil import iter_modules
from re import match, search, findall, compile
from subprocess import run, TimeoutExpired
from sys import modules
from threading import Thread
from time import time
from tld import get_tld
from typing import Optional, Dict, List, Any, Union

from assemblyline.common.str_utils import safe_str
from assemblyline.odm.base import FULL_URI, DOMAIN_REGEX, URI_PATH, IP_REGEX
from assemblyline_v4_service.common.balbuzard.patterns import PatternMatch
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT

import signatures
from signatures.abstracts import Signature

# Execution constants
WSCRIPT_SHELL = "wscript.shell"
WSCRIPT_SHELL_REGEX = r"(?i)(?:WScript.Shell\[\d\]\.Run\()(.*)(?:\))"
MAX_PAYLOAD_FILES_EXTRACTED = 50
RESOURCE_NOT_FOUND_SHA256 = "85658525ce99a2b0887f16b8a88d7acf4ae84649fa05217caf026859721ba04a"

# Signature Constants
TRANSLATED_SCORE = {
    0: 10,  # Informational
    1: 500,  # Suspicious
    2: 750,  # Highly Suspicious
    3: 1000,  # Malware
}


def truncate(data: Union[bytes, str], length: int = 100) -> str:
    """
    This method is a helper used to avoid cluttering output
    :param data: The buffer that will be determined if it needs to be sliced
    :param length: The limit of characters to the buffer
    :return str: The potentially truncated buffer
    """
    string = safe_str(data)
    if len(string) > length:
        return string[:length] + '...'
    return string


def get_id_from_data(file_path: str) -> str:
    """
    This method generates a sha256 hash for the file contents of a file
    :param file_path: The file path
    :return hash: The sha256 hash of the file
    """
    sha256_hash = sha256()
    # stream it in so we don't load the whole file in memory
    with open(file_path, 'rb') as f:
        data = f.read(4096)
        while data:
            sha256_hash.update(data)
            data = f.read(4096)
    return sha256_hash.hexdigest()


class JsJaws(ServiceBase):
    def __init__(self, config: Optional[Dict] = None) -> None:
        super(JsJaws, self).__init__(config)
        self.artifact_list: Optional[List[Dict[str, str]]] = None
        self.patterns = PatternMatch()
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
        self.log.debug('JsJaws service initialized')

    def start(self) -> None:
        self.log.debug('JsJaws service started')

    def stop(self) -> None:
        self.log.debug('JsJaws service ended')

    def execute(self, request: ServiceRequest) -> None:
        self.artifact_list = []

        # File constants
        self.malware_jail_payload_extraction_dir = path.join(self.working_directory, "payload/")
        self.malware_jail_sandbox_env_dump = "sandbox_dump.json"
        self.malware_jail_sandbox_env_dir = path.join(self.working_directory, "sandbox_env")
        self.malware_jail_sandbox_env_dump_path = path.join(self.malware_jail_sandbox_env_dir, self.malware_jail_sandbox_env_dump)
        root_dir = path.dirname(path.abspath(__file__))
        self.path_to_jailme_js = path.join(root_dir, "tools/jailme.js")
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

        # Setup directory structure
        if not path.exists(self.malware_jail_payload_extraction_dir):
            mkdir(self.malware_jail_payload_extraction_dir)

        if not path.exists(self.malware_jail_sandbox_env_dir):
            mkdir(self.malware_jail_sandbox_env_dir)

        request.result = Result()

        # Grabbing service level configuration variables and submission variables
        download_payload = request.get_param("download_payload")
        allow_download_from_internet = self.config.get("allow_download_from_internet", False)
        tool_timeout = request.get_param("tool_timeout")
        browser_selected = request.get_param("browser")
        wscript_only = request.get_param("wscript_only")
        throw_http_exc = request.get_param("throw_http_exc")
        extract_function_calls = request.get_param("extract_function_calls")
        extract_eval_calls = request.get_param("extract_eval_calls")
        add_supplementary = request.get_param("add_supplementary")
        static_signatures = request.get_param("static_signatures")
        no_shell_error = request.get_param("no_shell_error")
        display_sig_marks = request.get_param("display_sig_marks")

        # --loglevel             Logging level (debug, verbose, info, warning, error - default "info")
        # --no-kill              Do not kill the application when runtime errors occur
        # --output-dir           The location on disk to write the results files and folders to (defaults to the
        #                        current directory)
        boxjs_args = [self.path_to_boxjs, "--loglevel", "debug", "--no-kill", "--output-dir", self.working_directory]

        # -s odir  ... output directory for generated files (malware payload)
        # -o ofile ... name of the file where sandbox shall be dumped at the end
        # -b id    ... browser type, use -b list for possible values (Possible -b values:
        # [ 'IE11_W10', 'IE8', 'IE7', 'iPhone', 'Firefox', 'Chrome' ])
        malware_jail_args = [
            "node", self.path_to_jailme_js, "-s", self.malware_jail_payload_extraction_dir, "-o", self.malware_jail_sandbox_env_dump_path,
            "-b", browser_selected
        ]

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

        jsxray_args = ["node", self.path_to_jsxray]

        # Don't forget the sample!
        boxjs_args.append(request.file_path)
        malware_jail_args.append(request.file_path)
        jsxray_args.append(request.file_path)

        tool_threads: List[Thread] = []
        responses: Dict[str, List[str]] = {}
        tool_threads.append(Thread(target=self._run_tool, args=("Box.js", boxjs_args, tool_timeout, responses)))
        tool_threads.append(Thread(target=self._run_tool, args=("MalwareJail", malware_jail_args, tool_timeout, responses, True, True)))
        tool_threads.append(Thread(target=self._run_tool, args=("JS-X-Ray", jsxray_args, tool_timeout, responses, True)))

        for thr in tool_threads:
            thr.start()

        for thr in tool_threads:
            thr.join()

        boxjs_output: List[str] = []
        if path.exists(self.boxjs_analysis_log):
            with open(self.boxjs_analysis_log, "r") as f:
                boxjs_output = f.readlines()

        malware_jail_output = responses.get("MalwareJail", [])
        try:
            jsxray_output = loads(responses.get("JS-X-Ray", ""))
        except JSONDecodeError:
            jsxray_output: Dict[Any] = {}

        # ==================================================================
        # Magic Section
        # ==================================================================

        # We are running signatures based on the output observed from dynamic execution (boxjs_output and malware_jail_output)
        # as well as the file contents themselves (static analysis)
        if static_signatures:
            static_file_lines = []
            for line in safe_str(request.file_contents).split("\n"):
                if ";" in line:
                    static_file_lines.extend(line.split(";"))
                else:
                    static_file_lines.append(line)
            total_output = boxjs_output + malware_jail_output + static_file_lines
        else:
            total_output = boxjs_output + malware_jail_output
        self._run_signatures(total_output, request.result, display_sig_marks)

        self._extract_boxjs_iocs(request.result)
        self._extract_malware_jail_iocs(malware_jail_output, request.result)
        self._extract_wscript(total_output, request.result)
        self._extract_doc_writes(malware_jail_output)
        self._extract_payloads(request.sha256, request.deep_scan)
        self._extract_urls(request.result)
        if add_supplementary:
            self._extract_supplementary(malware_jail_output)
        self._flag_jsxray_iocs(jsxray_output, request.result)

        # Adding sandbox artifacts using the SandboxOntology helper class
        _ = SandboxOntology.handle_artifacts(self.artifact_list, request)

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
        wscript_res_sec = ResultSection("IOCs extracted from WScript")
        for line in output:
            wscript_shell_run = search(compile(WSCRIPT_SHELL_REGEX), line)
            # Script was run
            if wscript_shell_run:
                cmd = wscript_shell_run.group(1)
                # This is a byproduct of the sandbox using WScript.Shell.Run
                for item in [", 0, undefined", ", 1, 0"]:
                    if item in cmd:
                        cmd = cmd.replace(item, "")
                # Write command to file
                wscript_extraction.write(cmd + "\n")
                # Let's try to extract IOCs from it
                self._extract_iocs_from_text_blob(line, wscript_res_sec, ".js")
        wscript_extraction.close()

        if path.getsize(self.extracted_wscript_path) > 0:
            artifact = {
                "name": self.extracted_wscript,
                "path": self.extracted_wscript_path,
                "description": "Extracted WScript",
                "to_be_extracted": True
            }
            self.log.debug(f"Adding extracted file: {self.extracted_wscript}")
            self.artifact_list.append(artifact)
            if wscript_res_sec.tags != {}:
                result.add_section(wscript_res_sec)

    def _extract_payloads(self, sample_sha256: str, deep_scan: bool) -> None:
        """
        This method extracts unique payloads that were written to disk by MalwareJail
        :param sample_sha256: The SHA256 of the submitted file
        :param deep_scan: A boolean representing if the user has requested a deep scan
        :return: None
        """
        unique_shas = {sample_sha256}
        max_payloads_extracted = self.config.get("max_payloads_extracted", MAX_PAYLOAD_FILES_EXTRACTED)
        extracted_count = 0

        malware_jail_payloads = [(file, path.join(self.malware_jail_payload_extraction_dir, file))
                                 for file in sorted(listdir(self.malware_jail_payload_extraction_dir))]

        # These are dumped files from Box.js of js that was run successfully
        files_to_not_extract = set()
        if path.exists(self.boxjs_snippets):
            with open(self.boxjs_snippets, "r") as f:
                snippets = loads(f.read())
                for snippet in snippets:
                    files_to_not_extract.add(snippet)

        box_js_payloads = [(file, path.join(self.boxjs_output_dir, file))
                           for file in sorted(listdir(self.boxjs_output_dir)) if file not in files_to_not_extract]

        all_payloads = malware_jail_payloads + box_js_payloads

        for file, extracted in all_payloads:
            # No empty files
            if path.getsize(extracted) == 0:
                continue
            # These are not payloads
            if extracted in [self.malware_jail_urls_json_path, self.extracted_wscript_path,
                             self.extracted_doc_writes_path, self.boxjs_iocs, self.boxjs_resources, self.boxjs_snippets,
                             self.boxjs_analysis_log, self.boxjs_urls_json_path]:
                continue
            extracted_sha = get_id_from_data(extracted)
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
                    "to_be_extracted": True
                }
                self.log.debug(f"Adding extracted file: {safe_str(file)}")
                self.artifact_list.append(artifact)

    def _extract_doc_writes(self, output: List[str]) -> None:
        """
        This method writes all document writes to a file and adds that in an extracted file
        :param output: A list of strings where each string is a line of stdout from the MalwareJail tool
        :param result: A Result object containing the service results
        """
        extracted_doc_writes = open(self.extracted_doc_writes_path, "a+")
        doc_write = False
        for line in output:
            if doc_write:
                if " - => '" in line:
                    line = line.split(" - => '")[1]
                    if line.endswith("'"):
                        line = line[:-1]
                extracted_doc_writes.write(line + "\n")

            if all(item in line for item in ["document", "write(content)"]):
                doc_write = True
            else:
                doc_write = False
        extracted_doc_writes.close()

        if path.getsize(self.extracted_doc_writes_path) > 0:
            self.artifact_list.append({
                "name": self.extracted_doc_writes,
                "path": self.extracted_doc_writes_path,
                "description": "DOM Writes",
                "to_be_extracted": True
            })
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

        urls_result_section = ResultSection("URLs", body_format=BODY_FORMAT.TABLE)

        urls_json = []
        if path.exists(self.malware_jail_urls_json_path):
            with open(self.malware_jail_urls_json_path, "r") as f:
                file_contents = f.read()
                urls_json = loads(file_contents)
                for url in urls_json:
                    self._tag_uri(url["url"], urls_result_section)

        if path.exists(self.boxjs_iocs):
            with open(self.boxjs_iocs, "r") as f:
                file_contents = f.read()
                ioc_json = loads(file_contents)
                for ioc in ioc_json:
                    value = ioc["value"]
                    if ioc["type"] == "UrlFetch":
                        if any(value["url"] == url["url"] for url in urls_json):
                            continue
                        urls_json.append({"url": value["url"], "method": value["method"], "request_headers": value["headers"]})
                        self._tag_uri(value["url"], urls_result_section)

        if urls_json:
            urls_result_section.body = dumps(urls_json)
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
                "to_be_extracted": False
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
                "to_be_extracted": False
            }
            self.log.debug(f"Adding supplementary file: {self.malware_jail_output}")
            self.artifact_list.append(mlwr_jail_out)

        if path.exists(self.boxjs_analysis_log):
            boxjs_analysis_log = {
                "name": "boxjs_analysis_log.log",
                "path": self.boxjs_analysis_log,
                "description": "Box.js Output",
                "to_be_extracted": False
            }
            self.log.debug(f"Adding supplementary file: {self.boxjs_analysis_log}")
            self.artifact_list.append(boxjs_analysis_log)

    def _extract_iocs_from_text_blob(self, blob: str, result_section: ResultSection, file_ext: str = "") -> None:
        """
        This method searches for domains, IPs and URIs used in blobs of text and tags them
        :param blob: The blob of text that we will be searching through
        :param result_section: The result section that that tags will be added to
        :param file_ext: The file extension of the file to be submitted
        :return: None
        """
        blob = blob.lower()
        ips = set(findall(IP_REGEX, blob))
        # There is overlap here between regular expressions, so we want to isolate domains that are not ips
        domains = set(findall(DOMAIN_REGEX, blob)) - ips
        # There is overlap here between regular expressions, so we want to isolate uris that are not domains
        uris = set(findall(self.patterns.PAT_URI_NO_PROTOCOL, blob.encode()))
        uris = {uri.decode() for uri in uris} - domains - ips
        ioc_extracted = False

        for ip in ips:
            safe_ip = safe_str(ip)
            ioc_extracted = True
            result_section.add_tag("network.dynamic.ip", safe_ip)
        for domain in domains:
            if domain.lower() in [WSCRIPT_SHELL.lower()]:
                continue
            # File names match the domain and URI regexes, so we need to avoid tagging them
            # Note that get_tld only takes URLs so we will prepend http:// to the domain to work around this
            tld = get_tld(f"http://{domain}", fail_silently=True)
            if tld is None or f".{tld}" == file_ext:
                continue
            safe_domain = safe_str(domain)
            ioc_extracted = True
            result_section.add_tag("network.dynamic.domain", safe_domain)
        for uri in uris:
            # If there is a domain in the uri, then do
            if not any(ip in uri for ip in ips):
                try:
                    if not any(protocol in uri for protocol in ["http", "ftp", "icmp", "ssh"]):
                        tld = get_tld(f"http://{uri}", fail_silently=True)
                    else:
                        tld = get_tld(uri, fail_silently=True)
                except ValueError:
                    continue
                if tld is None or f".{tld}" == file_ext:
                    continue
            safe_uri = safe_str(uri)
            ioc_extracted = True
            result_section.add_tag("network.dynamic.uri", safe_uri)
            if "//" in safe_uri:
                safe_uri = safe_uri.split("//")[1]
            for uri_path in findall(URI_PATH, safe_uri):
                ioc_extracted = True
                result_section.add_tag("network.dynamic.uri_path", uri_path)
        if ioc_extracted and result_section.heuristic is None:
            result_section.set_heuristic(2)

    def _run_signatures(self, output: List[str], result: Result, display_sig_marks: bool = False) -> None:
        """
        This method sets up the parallelized signature engine and runs each signature against the
        stdout from MalwareJail
        :param output: A list of strings where each string is a line of stdout from the MalwareJail tool
        :param result: A Result object containing the service results
        :param display_sig_marks: A boolean indicating if we are going to include the signature marks in the
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
            thr = Thread(
                target=self._process_signature,
                args=(sig, output, signatures_that_hit)
            )
            sig_threads.append(thr)
            thr.start()

        for thread in sig_threads:
            thread.join()
        self.log.debug(f"Completed running {len(sigs)} signatures! Time elapsed: {round(time() - start_time)}s")

        # Adding signatures to results
        if len(signatures_that_hit) > 0:
            sigs_res_sec = ResultSection("Signatures")
            for sig_that_hit in signatures_that_hit:
                sig_res_sec = ResultSection(f"Signature: {type(sig_that_hit).__name__}", body=sig_that_hit.description, parent=sigs_res_sec)
                sig_res_sec.set_heuristic(sig_that_hit.heuristic_id)
                translated_score = TRANSLATED_SCORE[sig_that_hit.severity]
                sig_res_sec.heuristic.add_signature_id(sig_that_hit.name, score=translated_score)
                if display_sig_marks:
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
                    self.artifact_list.append({
                        "name": cmd_file_name,
                        "path": cmd_file_path,
                        "description": "Command Extracted",
                        "to_be_extracted": True
                    })
                    self.log.debug(f"Adding extracted file: {cmd_file_name}")
                    cmd_count += 1
                elif type == "FileWrite" and "file" in value:
                    file_writes.add(value["file"])
                elif type == "FileRead" and "file" in value:
                    file_reads.add(value["file"])
            if commands:
                cmd_result_section = ResultSection("The script ran the following commands", parent=ioc_result_section)
                cmd_result_section.add_lines(list(commands))
                [cmd_result_section.add_tag("dynamic.process.command_line", command) for command in list(commands)]
                self._extract_iocs_from_text_blob(cmd_result_section.body, cmd_result_section, ".js")
            if file_writes:
                file_writes_result_section = ResultSection("The script wrote the following files", parent=ioc_result_section)
                file_writes_result_section.add_lines(list(file_writes))
                [file_writes_result_section.add_tag("dynamic.process.file_name", file_write) for file_write in list(file_writes)]
            if file_reads:
                file_reads_result_section = ResultSection("The script read the following files", parent=ioc_result_section)
                file_reads_result_section.add_lines(list(file_reads))
                [file_reads_result_section.add_tag("dynamic.process.file_name", file_read) for file_read in list(file_reads)]

            if ioc_result_section.subsections:
                ioc_result_section.set_heuristic(2)
                result.add_section(ioc_result_section)

    def _tag_uri(self, url: str, urls_result_section: ResultSection) -> None:
        """
        This method tags components of a URI
        :param url: The url to be analyzed
        :param urls_result_section: The result section which will have the tags of the uri components added to it
        :return: None
        """
        safe_url = safe_str(url)
        # Extract URI
        uri_match = match(FULL_URI, safe_url)
        if uri_match:
            urls_result_section.add_tag("network.dynamic.uri", safe_url)
            # Extract domain
            domain_match = search(DOMAIN_REGEX, safe_url)
            if domain_match:
                domain = domain_match.group(0)
                urls_result_section.add_tag("network.dynamic.domain", domain)
            # Extract IP
            ip_match = search(IP_REGEX, safe_url)
            if ip_match:
                ip = ip_match.group(0)
                urls_result_section.add_tag("network.dynamic.ip", ip)
            # Extract URI path
            if "//" in safe_url:
                safe_url = safe_url.split("//")[1]
            uri_path_match = search(URI_PATH, safe_url)
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
        jsxray_iocs_result_section = ResultSection("JS-X-Ray IOCs Detected")
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
                jsxray_iocs_result_section.add_line(f"\t\tObfuscated code was found that was obfuscated by: "
                                                    f"{safe_str(val)}")
        if jsxray_iocs_result_section.body and len(jsxray_iocs_result_section.body) > 0:
            jsxray_iocs_result_section.set_heuristic(2)
            result.add_section(jsxray_iocs_result_section)

    def _extract_malware_jail_iocs(self, output: List[str], result: Result) -> None:
        malware_jail_res_sec = ResultSection("MalwareJail extracted the following IOCs")
        for line in output:
            self._extract_iocs_from_text_blob(line, malware_jail_res_sec, ".js")
        if len(malware_jail_res_sec.tags) > 0:
            result.add_section(malware_jail_res_sec)

    def _run_tool(self, tool_name: str, args: List[str], tool_timeout: int, resp: Dict[str, Any], get_stdout: bool = False, split: bool = False) -> None:
        self.log.debug(f"Running {tool_name}...")
        start_time = time()
        try:
            completed_process = run(args=args, capture_output=True, timeout=tool_timeout)
        except TimeoutExpired:
            completed_process = None
        self.log.debug(f"Completed running {tool_name}! Time elapsed: {round(time() - start_time)}s")

        if completed_process and get_stdout:
            if split:
                resp[tool_name] = completed_process.stdout.decode().split("\n")
            else:
                resp[tool_name] = completed_process.stdout.decode()
