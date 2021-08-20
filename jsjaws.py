import inspect
import pkgutil
import sys
import time
from typing import Optional, Dict, List
import subprocess
from os import mkdir, listdir, remove, path
from json import loads
from hashlib import sha256
from re import match, search, findall, compile, IGNORECASE
from tld import get_tld
from threading import Thread

from assemblyline.common.str_utils import safe_str
from assemblyline.odm.base import FULL_URI, DOMAIN_REGEX, URI_PATH, IP_REGEX
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultSection, Heuristic, BODY_FORMAT
from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
from assemblyline_v4_service.common.balbuzard.patterns import PatternMatch
import signatures

# File constants
SERVICE_DIR = "/tmp/jsjaws"
PAYLOAD_EXTRACTION_DIR = path.join(SERVICE_DIR, "payload/")
SANDBOX_ENV_DUMP = "sandbox_dump.json"
SANDBOX_ENV_DIR = path.join(SERVICE_DIR, "sandbox_env")
SANDBOX_ENV_DUMP_PATH = path.join(SERVICE_DIR, SANDBOX_ENV_DIR, SANDBOX_ENV_DUMP)
PATH_TO_JAILME_JS = "./malware-jail/jailme.js"
URLS_JSON_PATH = path.join(SERVICE_DIR, PAYLOAD_EXTRACTION_DIR, "urls.json")
WSCRIPT_ONLY_CONFIG = "./config_wscript_only.json"
EXTRACTED_WSCRIPT = "extracted_wscript.bat"
EXTRACTED_WSCRIPT_PATH = path.join(PAYLOAD_EXTRACTION_DIR, EXTRACTED_WSCRIPT)
MALWARE_JAIL_OUTPUT = "output.txt"
MALWARE_JAIL_OUTPUT_PATH = path.join(SERVICE_DIR, MALWARE_JAIL_OUTPUT)

# Execution constants
WSCRIPT_SHELL = "wscript.shell"
WSCRIPT_SHELL_REGEX = r"(?i)(?:WScript.Shell\[\d\]\.Run\()(.*)(?:\))"
MAX_PAYLOAD_FILES_EXTRACTED = 50

# Signature Constants
TRANSLATED_SCORE = {
    0: 10,  # Informational
    1: 500,  # Suspicious
    2: 750,  # Highly Suspicious
    3: 1000,  # Malware
}


class JsJaws(ServiceBase):
    def __init__(self, config: Optional[Dict] = None) -> None:
        super(JsJaws, self).__init__(config)
        self.artifact_list: Optional[List[Dict[str, str]]] = None
        self.patterns = PatternMatch()
        self.log.info('JsJaws service initializing')

    def start(self) -> None:
        self.log.info('JsJaws service started')
        self.artifact_list = []
        if not path.exists(SERVICE_DIR):
            mkdir(SERVICE_DIR)

        if not path.exists(PAYLOAD_EXTRACTION_DIR):
            mkdir(PAYLOAD_EXTRACTION_DIR)

        if not path.exists(SANDBOX_ENV_DIR):
            mkdir(SANDBOX_ENV_DIR)

    def stop(self) -> None:
        self.log.info('JsJaws service ended')

    def execute(self, request: ServiceRequest) -> None:

        self._cleanup_previous_exec()
        request.result = Result()

        browser_selected = request.get_param("browser")
        wscript_only = request.get_param("wscript_only")
        download_payload = request.get_param("download_payload")
        allow_download_from_internet = self.config.get("allow_download_from_internet", False)
        throw_http_exc = request.get_param("throw_http_exc")
        extract_function_calls = request.get_param("extract_function_calls")
        extract_eval_calls = request.get_param("extract_eval_calls")

        args = ["node", PATH_TO_JAILME_JS, "-s", PAYLOAD_EXTRACTION_DIR, "-o", SANDBOX_ENV_DUMP_PATH, "-b", browser_selected]

        if allow_download_from_internet and download_payload:
            args.append("--down=y")
        elif not allow_download_from_internet and download_payload:
            request.result.add_section(ResultSection("Internet Access is disabled."))

        if throw_http_exc:
            args.append("--t404")
        else:
            args.append("--h404")

        if request.deep_scan or extract_function_calls:
            args.append("--extractfns")

        if request.deep_scan or extract_eval_calls:
            args.append("--extractevals")

        if wscript_only:
            args.extend(["-c", WSCRIPT_ONLY_CONFIG])

        args.append(request.file_path)

        self.log.debug("Running MalwareJail...")
        start_time = time.time()
        completed_process = subprocess.run(args=args, capture_output=True)
        self.log.debug(f"Completed running MalwareJail! Time elapsed: {round(time.time() - start_time)}s")

        output = completed_process.stdout.decode().split("\n")

        self._run_signatures(output, request.result)
        self._extract_wscript(output, request)
        self._extract_payloads(request.sha256, request.deep_scan)
        self._extract_urls(request)
        self._extract_supplementary(output)

        # Adding sandbox artifacts using the SandboxOntology helper class
        _ = SandboxOntology.handle_artifacts(self.artifact_list, request)

    @staticmethod
    def _cleanup_previous_exec():
        for file in listdir(PAYLOAD_EXTRACTION_DIR):
            remove(path.join(PAYLOAD_EXTRACTION_DIR, file))
        if path.exists(SANDBOX_ENV_DUMP_PATH):
            remove(SANDBOX_ENV_DUMP_PATH)
        if path.exists(EXTRACTED_WSCRIPT_PATH):
            remove(EXTRACTED_WSCRIPT_PATH)

    def _extract_wscript(self, output, request):
        wscript_extracted = False
        wscript_extraction = open(EXTRACTED_WSCRIPT_PATH, "a+")
        wscript_res_sec = ResultSection("IOCs extracted from WScript")
        for line in output:
            wscript_shell_run = search(compile(WSCRIPT_SHELL_REGEX), line)
            if wscript_shell_run:
                cmd = wscript_shell_run.group(1)
                # This is a byproduct of the sandbox using WScript.Shell.Run
                for item in [", 0, undefined", ", 1, 0"]:
                    if item in cmd:
                        cmd = cmd.replace(item, "")
                wscript_extraction.write(cmd + "\n")
                wscript_extracted = True
                # Script was run, let's try to extract it
                self._extract_iocs_from_text_blob(line, wscript_res_sec, ".js")

        wscript_extraction.close()
        if wscript_extracted:
            artifact = {
                "name": EXTRACTED_WSCRIPT,
                "path": EXTRACTED_WSCRIPT_PATH,
                "description": "Extracted WScript",
                "to_be_extracted": True
            }
            self.log.debug(f"Adding extracted file: {EXTRACTED_WSCRIPT}")
            self.artifact_list.append(artifact)
            if wscript_res_sec.tags != {}:
                request.result.add_section(wscript_res_sec)

    def _extract_payloads(self, sha256, deep_scan):
        unique_shas = {sha256}
        max_payloads_extracted = self.config.get("max_payloads_extracted", MAX_PAYLOAD_FILES_EXTRACTED)
        extracted_count = 0
        for file in listdir(PAYLOAD_EXTRACTION_DIR):
            extracted = path.join(PAYLOAD_EXTRACTION_DIR, file)
            # No empty files
            if path.getsize(extracted) == 0:
                continue
            # No files that we added ourselves or will parse later
            if extracted in [URLS_JSON_PATH, EXTRACTED_WSCRIPT_PATH]:
                continue
            extracted_sha = get_id_from_data(extracted)
            if extracted_sha not in unique_shas:
                extracted_count += 1
                if not deep_scan and extracted_count >= max_payloads_extracted:
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

    @staticmethod
    def _extract_urls(request):
        if path.exists(URLS_JSON_PATH):
            urls_result_section = ResultSection("URLs", body_format=BODY_FORMAT.TABLE)
            with open(URLS_JSON_PATH, "r") as f:
                file_contents = f.read()
                urls_json = loads(file_contents)
                for url in urls_json:
                    safe_url = safe_str(url["url"])
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
                        urls_result_section.add_tag("file.string.extracted", safe_url)
                urls_result_section.body = file_contents
            urls_result_section.set_heuristic(1)
            request.result.add_section(urls_result_section)

    def _extract_supplementary(self, output):
        # Get the sandbox env json that is dumped
        sandbox_env_dump = {
            "name": SANDBOX_ENV_DUMP,
            "path": SANDBOX_ENV_DUMP_PATH,
            "description": "Sandbox Environment Details",
            "to_be_extracted": False
        }
        self.log.debug(f"Adding supplementary file: {SANDBOX_ENV_DUMP}")
        self.artifact_list.append(sandbox_env_dump)

        if output:
            with open(MALWARE_JAIL_OUTPUT_PATH, "w") as f:
                for line in output:
                    f.write(line + "\n")
            mlwr_jail_out = {
                "name": MALWARE_JAIL_OUTPUT,
                "path": MALWARE_JAIL_OUTPUT_PATH,
                "description": "Malware Jail Output",
                "to_be_extracted": False
            }
            self.log.debug(f"Adding supplementary file: {MALWARE_JAIL_OUTPUT}")
            self.artifact_list.append(mlwr_jail_out)

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

    def _run_signatures(self, output: List[str], result: Result) -> None:
        """

        """
        # Loading signatures
        sigs = []
        prefix = f"{signatures.__name__}."
        abstracts = "signatures.abstracts"
        signature_class = "Signature"
        for importer, modname, ispkg in pkgutil.iter_modules(signatures.__path__, prefix):
            if modname == abstracts:
                continue
            __import__(modname)
            clsmembers = inspect.getmembers(sys.modules[modname], inspect.isclass)
            for cls in clsmembers:
                name, obj = cls
                if name == signature_class:
                    continue
                sigs.append(obj())

        # Running signatures
        signatures_that_hit = []
        sig_threads = []

        self.log.debug(f"Running {len(sigs)} signatures...")
        start_time = time.time()
        for sig in sigs:
            thr = Thread(
                target=self._process_signature,
                args=(sig, output, signatures_that_hit)
            )
            sig_threads.append(thr)
            thr.start()

        for thread in sig_threads:
            thread.join()
        self.log.debug(f"Completed running {len(sigs)} signatures! Time elapsed: {round(time.time() - start_time)}s")

        # Adding signatures to results
        if len(signatures_that_hit) > 0:
            sigs_res_sec = ResultSection("Signatures")
            for sig_that_hit in signatures_that_hit:
                sig_res_sec = ResultSection(f"Signature: {sig_that_hit.name}", body=sig_that_hit.description, parent=sigs_res_sec)
                sig_res_sec.set_heuristic(sig_that_hit.heuristic_id)
                translated_score = TRANSLATED_SCORE[sig_that_hit.severity]
                sig_res_sec.heuristic.add_signature_id(sig_that_hit.name, score=translated_score)
                for mark in sig_that_hit.marks:
                    sig_res_sec.add_line(f"\t\t{mark}")

            result.add_section(sigs_res_sec)

    @staticmethod
    def _process_signature(signature, output, signatures_that_hit):
        signature.process_output(output)
        if len(signature.marks) > 0:
            signatures_that_hit.append(signature)


def get_id_from_data(file_path: str) -> str:
    """
    This method generates a sha256 hash for the file contents of a file
    @param file_path: The file path
    @return _hash: The sha256 hash of the file
    """
    sha256_hash = sha256()
    # stream it in so we don't load the whole file in memory
    with open(file_path, 'rb') as f:
        data = f.read(4096)
        while data:
            sha256_hash.update(data)
            data = f.read(4096)
    return sha256_hash.hexdigest()
