from typing import Optional, Dict, List
import subprocess
from os import mkdir, listdir, remove, path
from json import loads
from hashlib import sha256
from re import match, search, findall
from tld import get_tld

from assemblyline.common.str_utils import safe_str
from assemblyline.odm.base import FULL_URI, DOMAIN_REGEX, URI_PATH, IP_REGEX
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultSection, Heuristic, BODY_FORMAT
from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
from assemblyline_v4_service.common.balbuzard.patterns import PatternMatch

# File constants
SERVICE_DIR = "/tmp/jsjaws"
PAYLOAD_EXTRACTION_DIR = path.join(SERVICE_DIR, "payload/")
SANDBOX_ENV_DUMP = "sandbox_dump.json"
SANDBOX_ENV_DIR = path.join(SERVICE_DIR, "sandbox_env")
SANDBOX_ENV_DUMP_PATH = path.join(SERVICE_DIR, SANDBOX_ENV_DIR, SANDBOX_ENV_DUMP)
PATH_TO_JAILME_JS = "./malware-jail/jailme.js"
URLS_JSON_PATH = path.join(SERVICE_DIR, PAYLOAD_EXTRACTION_DIR, "urls.json")
WSCRIPT_ONLY_CONFIG = "./config_wscript_only.json"
EXTRACTED_WSCRIPT = "extracted_wscript.js"
EXTRACTED_WSCRIPT_PATH = path.join(PAYLOAD_EXTRACTION_DIR, EXTRACTED_WSCRIPT)
MALWARE_JAIL_OUTPUT = "output.txt"
MALWARE_JAIL_OUTPUT_PATH = path.join(SERVICE_DIR, MALWARE_JAIL_OUTPUT)

# Execution constants
WSCRIPT_SHELL = "WScript.Shell"
INVALID_URI_CHARS_FOR_TLD = "',"


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

        browser_selected = request.get_param("browser")
        wscript_only = request.get_param("wscript_only")

        args = ["node", PATH_TO_JAILME_JS, "-s", PAYLOAD_EXTRACTION_DIR, "-o", SANDBOX_ENV_DUMP_PATH, "-b", browser_selected]

        if self.config.get("allow_download", False):
            args.append("--down=y")
        else:
            args.append("--h404")

        if wscript_only:
            args.extend(["-c", WSCRIPT_ONLY_CONFIG])

        args.append(request.file_path)

        completed_process = subprocess.run(args=args, capture_output=True)
        output = completed_process.stdout.decode().split("\n")

        request.result = Result()

        self._extract_supplementary(output)
        self._extract_wscript(output, request)
        self._extract_payloads(request.sha256)
        self._extract_urls(request)

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
            if WSCRIPT_SHELL.lower() in line.lower():
                # Script was run, let's try to extract it
                run_date, js = line.split(" - ")
                self._extract_iocs_from_text_blob(line, wscript_res_sec, ".js")
                wscript_extraction.write(js + "\n")
                wscript_extracted = True
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
            request.result.add_section(wscript_res_sec)

    def _extract_payloads(self, sha256):
        unique_shas = {sha256}
        for file in listdir(PAYLOAD_EXTRACTION_DIR):
            extracted = path.join(PAYLOAD_EXTRACTION_DIR, file)
            if extracted in [URLS_JSON_PATH, EXTRACTED_WSCRIPT_PATH]:
                continue
            extracted_sha = get_id_from_data(extracted)
            if extracted_sha not in unique_shas:
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
            tld = None
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
        if ioc_extracted:
            result_section.set_heuristic(2)


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
