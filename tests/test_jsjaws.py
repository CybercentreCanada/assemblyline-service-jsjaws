import os
import shutil
from hashlib import sha256
from json import dumps
from os import mkdir, path, remove
from os.path import exists, join
from subprocess import TimeoutExpired

import pytest
from assemblyline.common.identify import Identify
from assemblyline.odm.messages.task import Task as ServiceTask
from assemblyline_service_utilities.common.dynamic_service_helper import OntologyResults
from assemblyline_service_utilities.testing.helper import check_section_equality
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import BODY_FORMAT, Result, ResultSection, ResultTableSection, TableRow
from assemblyline_v4_service.common.task import Task
from jsjaws import JsJaws
from signatures.abstracts import Signature

# Getting absolute paths, names and regexes
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(TEST_DIR)
SERVICE_CONFIG_NAME = "service_manifest.yml"
SERVICE_CONFIG_PATH = os.path.join(ROOT_DIR, SERVICE_CONFIG_NAME)
TEMP_SERVICE_CONFIG_PATH = os.path.join("/tmp", SERVICE_CONFIG_NAME)

# Samples that we will be sending to the service
samples = [
    dict(
        sid=1,
        metadata={},
        service_name="jsjaws",
        service_config={},
        fileinfo=dict(
            magic="ASCII text, with no line terminators",
            md5="fda4e701258ba56f465e3636e60d36ec",
            mime="text/plain",
            sha1="af2c2618032c679333bebf745e75f9088748d737",
            sha256="dadc624d4454e10293dbd1b701b9ee9f99ef83b4cd07b695111d37eb95abcff8",
            size=19,
            type="unknown",
        ),
        filename="dadc624d4454e10293dbd1b701b9ee9f99ef83b4cd07b695111d37eb95abcff8",
        min_classification="TLP:WHITE",
        max_files=501,  # TODO: get the actual value
        ttl=3600,
        safelist_config={"enabled": False, "hash_types": ["sha1", "sha256"], "enforce_safelist_service": False},
    ),
]


def create_tmp_manifest():
    temp_service_config_path = os.path.join("/tmp", SERVICE_CONFIG_NAME)
    if not os.path.exists(temp_service_config_path):
        # Placing the service_manifest.yml in the tmp directory
        shutil.copyfile(SERVICE_CONFIG_PATH, temp_service_config_path)


def remove_tmp_manifest():
    temp_service_config_path = os.path.join("/tmp", SERVICE_CONFIG_NAME)
    if os.path.exists(temp_service_config_path):
        os.remove(temp_service_config_path)


@pytest.fixture
def dummy_task_class():
    class DummyTask:
        def __init__(self):
            self.supplementary = []
            self.extracted = []
            self.file_name = "blah.js"

    yield DummyTask


@pytest.fixture
def dummy_request_class_instance(dummy_task_class):
    class DummyRequest:
        SERVICE_CONFIG = {
            "browser": "IE8",
            "wscript_only": False,
            "throw_http_exc": False,
            "download_payload": False,
            "extract_function_calls": False,
            "extract_eval_calls": False,
            "tool_timeout": 60,
            "add_supplementary": False,
            "static_signatures": True,
            "no_shell_error": False,
            "display_iocs": False,
            "log_errors": False,
            "static_analysis_only": False,
            "enable_synchrony": False,
            "override_eval": False,
            "file_always_exists": False,
        }

        def __init__(self):
            super(DummyRequest, self).__init__()
            self.temp_submission_data = {}
            self.result = None
            self.file_contents = b""
            self.file_type = "code/html"
            self.sha256 = sha256(self.file_contents).hexdigest()
            self.deep_scan = False
            self.task = dummy_task_class()

        def add_supplementary(*args):
            pass

        def get_param(self, param):
            return self.SERVICE_CONFIG[param]

    yield DummyRequest()


@pytest.fixture
def jsjaws_class_instance():
    create_tmp_manifest()
    try:
        yield JsJaws()
    finally:
        remove_tmp_manifest()


@pytest.fixture
def dummy_completed_process_instance():
    class DummyCompletedProcess:
        def __init__(self):
            self.stdout = b"[29 Jun 08:24:36] blah\n[29 Jun 08:24:37] blah"

    yield DummyCompletedProcess()


@pytest.fixture
def dummy_get_response_class():
    class DummyGetResponse:
        def __init__(self, text):
            self.text = text

    yield DummyGetResponse


class TestJsJaws:
    @classmethod
    def setup_class(cls):
        # Placing the samples in the tmp directory
        samples_path = os.path.join(TEST_DIR, "samples")
        for sample in os.listdir(samples_path):
            sample_path = os.path.join(samples_path, sample)
            shutil.copyfile(sample_path, os.path.join("/tmp", sample))

    @classmethod
    def teardown_class(cls):
        # Cleaning up the tmp directory
        samples_path = os.path.join(TEST_DIR, "samples")
        for sample in os.listdir(samples_path):
            temp_sample_path = os.path.join("/tmp", sample)
            os.remove(temp_sample_path)

    @staticmethod
    def test_init(jsjaws_class_instance):
        assert jsjaws_class_instance.artifact_list is None
        assert jsjaws_class_instance.malware_jail_payload_extraction_dir is None
        assert jsjaws_class_instance.malware_jail_sandbox_env_dump is None
        assert jsjaws_class_instance.malware_jail_sandbox_env_dir is None
        assert jsjaws_class_instance.malware_jail_sandbox_env_dump_path is None
        assert jsjaws_class_instance.path_to_jailme_js is None
        assert jsjaws_class_instance.path_to_boxjs is None
        assert jsjaws_class_instance.boxjs_urls_json_path is None
        assert jsjaws_class_instance.malware_jail_urls_json_path is None
        assert jsjaws_class_instance.wscript_only_config is None
        assert jsjaws_class_instance.extracted_wscript_batch is None
        assert jsjaws_class_instance.extracted_wscript_ps1 is None
        assert jsjaws_class_instance.extracted_wscript_batch_path is None
        assert jsjaws_class_instance.extracted_wscript_ps1_path is None
        assert jsjaws_class_instance.boxjs_batch is None
        assert jsjaws_class_instance.boxjs_batch_path is None
        assert jsjaws_class_instance.boxjs_ps1 is None
        assert jsjaws_class_instance.boxjs_ps1_path is None
        assert jsjaws_class_instance.malware_jail_output is None
        assert jsjaws_class_instance.malware_jail_output_path is None
        assert jsjaws_class_instance.boxjs_output_dir is None
        assert jsjaws_class_instance.boxjs_iocs is None
        assert jsjaws_class_instance.boxjs_resources is None
        assert jsjaws_class_instance.boxjs_analysis_log is None
        assert jsjaws_class_instance.boxjs_snippets is None
        assert jsjaws_class_instance.cleaned_with_synchrony is None
        assert jsjaws_class_instance.cleaned_with_synchrony_path is None
        assert jsjaws_class_instance.stdout_limit is None
        assert isinstance(jsjaws_class_instance.identify, Identify)
        assert jsjaws_class_instance.safelist == {}
        assert jsjaws_class_instance.doc_write_hashes is None

    @staticmethod
    def test_start(jsjaws_class_instance):
        jsjaws_class_instance.start()
        assert True

    @staticmethod
    def test_stop(jsjaws_class_instance):
        jsjaws_class_instance.stop()
        assert True

    @staticmethod
    @pytest.mark.parametrize("sample", samples)
    def test_execute(sample, jsjaws_class_instance, mocker):
        mocker.patch.object(jsjaws_class_instance, "_run_signatures")
        mocker.patch.object(jsjaws_class_instance, "_extract_boxjs_iocs")
        mocker.patch.object(jsjaws_class_instance, "_extract_wscript")
        mocker.patch.object(jsjaws_class_instance, "_extract_doc_writes")
        mocker.patch.object(jsjaws_class_instance, "_extract_payloads")
        mocker.patch.object(jsjaws_class_instance, "_extract_urls")
        mocker.patch.object(jsjaws_class_instance, "_extract_supplementary")
        mocker.patch.object(jsjaws_class_instance, "_flag_jsxray_iocs")
        mocker.patch.object(OntologyResults, "handle_artifacts")
        mocker.patch.object(jsjaws_class_instance, "_run_tool")

        service_task = ServiceTask(sample)
        task = Task(service_task)
        task.service_config = {
            "browser": "IE8",
            "wscript_only": False,
            "throw_http_exc": False,
            "download_payload": False,
            "extract_function_calls": False,
            "extract_eval_calls": False,
            "tool_timeout": 60,
            "add_supplementary": False,
            "static_signatures": True,
            "no_shell_error": False,
            "display_iocs": False,
            "log_errors": False,
            "override_eval": False,
            "file_always_exists": False,
            "static_analysis_only": False,
            "enable_synchrony": False,
            "ignore_stdout_limit": False,
        }
        jsjaws_class_instance._task = task
        service_request = ServiceRequest(task)

        jsjaws_class_instance.boxjs_output_dir = path.join(
            jsjaws_class_instance.working_directory, f"{service_request.sha256}.results"
        )
        jsjaws_class_instance.boxjs_analysis_log = path.join(jsjaws_class_instance.boxjs_output_dir, "analysis.log")
        mkdir(jsjaws_class_instance.boxjs_output_dir)
        with open(jsjaws_class_instance.boxjs_analysis_log, "w") as f:
            f.write("blah\nblah\nblah")

        # Actually executing the sample
        jsjaws_class_instance.execute(service_request)

        assert jsjaws_class_instance.artifact_list == []
        assert jsjaws_class_instance.malware_jail_payload_extraction_dir == path.join(
            jsjaws_class_instance.working_directory, "payload/"
        )
        assert jsjaws_class_instance.malware_jail_sandbox_env_dump == "sandbox_dump.json"
        assert jsjaws_class_instance.malware_jail_sandbox_env_dir == path.join(
            jsjaws_class_instance.working_directory, "sandbox_env"
        )
        assert jsjaws_class_instance.malware_jail_sandbox_env_dump_path == path.join(
            jsjaws_class_instance.malware_jail_sandbox_env_dir, jsjaws_class_instance.malware_jail_sandbox_env_dump
        )
        root_dir = path.dirname(path.dirname(path.abspath(__file__)))
        assert jsjaws_class_instance.path_to_jailme_js == path.join(root_dir, "tools/malwarejail/jailme.js")
        assert jsjaws_class_instance.malware_jail_urls_json_path == path.join(
            jsjaws_class_instance.malware_jail_payload_extraction_dir, "urls.json"
        )
        assert jsjaws_class_instance.wscript_only_config == path.join(
            root_dir, "tools/malwarejail/config/config_wscript_only.json"
        )
        assert jsjaws_class_instance.extracted_wscript_batch == "extracted_wscript.bat"
        assert jsjaws_class_instance.extracted_wscript_batch_path == path.join(
            jsjaws_class_instance.malware_jail_payload_extraction_dir, jsjaws_class_instance.extracted_wscript_batch
        )
        assert jsjaws_class_instance.malware_jail_output == "output.txt"
        assert jsjaws_class_instance.malware_jail_output_path == path.join(
            jsjaws_class_instance.working_directory, jsjaws_class_instance.malware_jail_output
        )

        assert path.exists(jsjaws_class_instance.malware_jail_payload_extraction_dir)
        assert path.exists(jsjaws_class_instance.malware_jail_sandbox_env_dir)

        # Code coverage
        jsjaws_class_instance.config = {"allow_download_from_internet": True}
        service_request.task.service_config["download_payload"] = True
        jsjaws_class_instance.execute(service_request)

        jsjaws_class_instance.config = {"allow_download_from_internet": False}
        jsjaws_class_instance.execute(service_request)
        assert check_section_equality(service_request.result.sections[0], ResultSection("Internet Access is disabled."))

        service_request.task.service_config["download_payload"] = False
        service_request.task.service_config["throw_http_exception"] = True
        jsjaws_class_instance.execute(service_request)

        service_request.task.deep_scan = True
        jsjaws_class_instance.execute(service_request)

        service_request.task.deep_scan = False
        service_request.task.service_config["extract_function_calls"] = True
        service_request.task.service_config["extract_eval_calls"] = True
        service_request.task.service_config["wscript_only"] = True
        service_request.task.service_config["throw_http_exc"] = True
        service_request.task.service_config["no_shell_error"] = True
        service_request.task.service_config["static_signatures"] = False
        service_request.task.service_config["add_supplementary"] = True
        service_request.task.service_config["log_errors"] = True
        service_request.task.service_config["enable_synchrony"] = True
        service_request.task.service_config["static_analysis_only"] = True
        service_request.task.service_config["file_always_exists"] = True
        mocker.patch("jsjaws.Popen", side_effect=TimeoutExpired("blah", 1))
        jsjaws_class_instance.execute(service_request)

    @staticmethod
    def test_extract_wscript(jsjaws_class_instance, mocker):
        jsjaws_class_instance.payload_extraction_dir = join(jsjaws_class_instance.working_directory, "payload/")
        jsjaws_class_instance.extracted_wscript_batch = "extracted_wscript.bat"
        jsjaws_class_instance.extracted_wscript_ps1 = "extracted_wscript.ps1"
        jsjaws_class_instance.extracted_wscript_batch_path = join(
            jsjaws_class_instance.payload_extraction_dir, jsjaws_class_instance.extracted_wscript_batch
        )
        jsjaws_class_instance.extracted_wscript_ps1_path = join(
            jsjaws_class_instance.payload_extraction_dir, jsjaws_class_instance.extracted_wscript_ps1
        )
        mkdir(jsjaws_class_instance.payload_extraction_dir)
        mocker.patch("jsjaws.extract_iocs_from_text_blob")
        output = ["WScript.Shell[4].Run(super evil script, 0, undefined)"]
        res = Result()
        jsjaws_class_instance.artifact_list = []
        jsjaws_class_instance._extract_wscript(output, res)
        assert exists(jsjaws_class_instance.extracted_wscript_batch_path)
        assert jsjaws_class_instance.artifact_list[0] == {
            "name": jsjaws_class_instance.extracted_wscript_batch,
            "path": jsjaws_class_instance.extracted_wscript_batch_path,
            "description": "Extracted WScript batch file",
            "to_be_extracted": True,
        }

    @staticmethod
    def test_extract_doc_writes_one_liners(jsjaws_class_instance, dummy_request_class_instance, mocker):
        # Single line example : 697b0e897a7d57e600a1020886f837469ffb87acc65f04c2ae424af50a311c7e
        # Multiple calls to document.write() (with multiline) example :
        # 4b19570cb328f4e47a44e04a74c94993225203260607f615a875cd58500c9abb

        jsjaws_class_instance.doc_write_hashes = set()
        jsjaws_class_instance.stdout_limit = 10000
        jsjaws_class_instance.boxjs_analysis_log = "blah"
        jsjaws_class_instance.gauntlet_runs = 0
        root_dir = os.path.dirname(os.path.abspath(__file__))

        jsjaws_class_instance.path_to_jailme_js = os.path.join(root_dir, "../", "tools/malwarejail/jailme.js")
        jsjaws_class_instance.path_to_jsxray = os.path.join(root_dir, "../", "tools/js-x-ray-run.js")
        jsjaws_class_instance.malware_jail_payload_extraction_dir = os.path.join(
            jsjaws_class_instance.working_directory, "payload/"
        )
        jsjaws_class_instance.malware_jail_sandbox_env_dump = "sandbox_dump.json"
        jsjaws_class_instance.malware_jail_sandbox_env_dir = os.path.join(
            jsjaws_class_instance.working_directory, "sandbox_env"
        )
        jsjaws_class_instance.malware_jail_sandbox_env_dump_path = os.path.join(
            jsjaws_class_instance.malware_jail_sandbox_env_dir, jsjaws_class_instance.malware_jail_sandbox_env_dump
        )

        mocker.patch.object(jsjaws_class_instance, "_extract_boxjs_iocs")
        mocker.patch.object(jsjaws_class_instance, "_extract_wscript")
        mocker.patch.object(jsjaws_class_instance, "_extract_payloads")
        mocker.patch.object(jsjaws_class_instance, "_extract_urls")
        mocker.patch.object(jsjaws_class_instance, "_extract_synchrony")

        output = [
            "[2022-10-18T20:12:49.924Z] document[15].write(content) 0 bytes",
            "[2022-10-18T20:12:50.924Z] => 'write me!'",
            "[2022-10-18T20:12:51.924Z] => Something else",
            "[2022-10-18T20:12:52.924Z] document[15].write(content) 0 bytes",
            "[2022-10-18T20:12:53.924Z] => 'write me too!'",
            "[2022-10-18T20:12:52.924Z] document[15].write(content) 0 bytes",
            "[2022-10-18T20:12:53.924Z] => 'password?!'",
        ]
        jsjaws_class_instance._extract_doc_writes(output, dummy_request_class_instance)
        expected_doc_write = "write me!write me too!password?!"
        assert jsjaws_class_instance.doc_write_hashes == {sha256(expected_doc_write.encode()).hexdigest()}
        assert dummy_request_class_instance.temp_submission_data.get("passwords") == [
            "me",
            "me!",
            "password",
            "password?!",
            "too",
            "too!",
            "write",
        ]

    @staticmethod
    def test_extract_doc_writes_multiliner(jsjaws_class_instance, dummy_request_class_instance, mocker):
        # Multiple calls to document.write() (with multiline) example :
        # 4b19570cb328f4e47a44e04a74c94993225203260607f615a875cd58500c9abb

        jsjaws_class_instance.doc_write_hashes = set()
        jsjaws_class_instance.stdout_limit = 10000
        jsjaws_class_instance.gauntlet_runs = 0

        output = [
            "[2022-10-18T20:12:49.924Z] document[15].write(content) 0 bytes",
            "[2022-10-18T20:12:50.924Z] => '",
            "<html>",
            "password: yabadabadoo",
            "</html>'",
            "[2022-10-18T20:12:51.924Z] - Something else",
        ]
        jsjaws_class_instance._extract_doc_writes(output, dummy_request_class_instance)
        expected_doc_write = "<html>\npassword: yabadabadoo\n</html>"
        assert jsjaws_class_instance.doc_write_hashes == {sha256(expected_doc_write.encode()).hexdigest()}
        assert dummy_request_class_instance.temp_submission_data.get("passwords") == [
            " yabadabadoo",
            "password",
            "password:",
            "yabadabadoo",
        ]

        dummy_request_class_instance.temp_submission_data = {}
        jsjaws_class_instance.doc_write_hashes = set()
        jsjaws_class_instance.gauntlet_runs = 0

        jsjaws_class_instance.boxjs_analysis_log = "blah"
        root_dir = os.path.dirname(os.path.abspath(__file__))

        jsjaws_class_instance.path_to_jailme_js = os.path.join(root_dir, "../", "tools/malwarejail/jailme.js")
        jsjaws_class_instance.path_to_jsxray = os.path.join(root_dir, "../", "tools/js-x-ray-run.js")
        jsjaws_class_instance.malware_jail_payload_extraction_dir = os.path.join(
            jsjaws_class_instance.working_directory, "payload/"
        )
        jsjaws_class_instance.malware_jail_sandbox_env_dump = "sandbox_dump.json"
        jsjaws_class_instance.malware_jail_sandbox_env_dir = os.path.join(
            jsjaws_class_instance.working_directory, "sandbox_env"
        )
        jsjaws_class_instance.malware_jail_sandbox_env_dump_path = os.path.join(
            jsjaws_class_instance.malware_jail_sandbox_env_dir, jsjaws_class_instance.malware_jail_sandbox_env_dump
        )

        mocker.patch.object(jsjaws_class_instance, "_extract_boxjs_iocs")
        mocker.patch.object(jsjaws_class_instance, "_extract_wscript")
        mocker.patch.object(jsjaws_class_instance, "_extract_payloads")
        mocker.patch.object(jsjaws_class_instance, "_extract_urls")
        mocker.patch.object(jsjaws_class_instance, "_extract_synchrony")

        multiple_gauntlet_output = [
            "[2022-12-21T21:06:23.655Z] document[6].write(content) 173 bytes",
            '[2022-12-21T21:06:23.655Z] => \'<html><script>var b64_encoded = "PGh0bWw+CnBhc3N3b3JkOiB5YWJhZGFiYWRvbwo8L2h0bWw+";',
            "    var b64_decoded = atob(b64_encoded);",
            "    document.write(b64_decoded);</script></html>'",
            "[2022-12-21T21:06:23.657Z] ==> Cleaning up sandbox.",
        ]
        jsjaws_class_instance._extract_doc_writes(multiple_gauntlet_output, dummy_request_class_instance)
        expected_doc_write_1 = b'<html><script>var b64_encoded = "PGh0bWw+CnBhc3N3b3JkOiB5YWJhZGFiYWRvbwo8L2h0bWw+";\n    var b64_decoded = atob(b64_encoded);\n    document.write(b64_decoded);</script></html>'
        expected_doc_write_2 = b"<html>\n\npassword: yabadabadoo\n\n</html>"
        assert jsjaws_class_instance.doc_write_hashes == {
            sha256(expected_doc_write_1).hexdigest(),
            sha256(expected_doc_write_2).hexdigest(),
        }
        assert dummy_request_class_instance.temp_submission_data.get("passwords") == [
            " yabadabadoo",
            "password",
            "password:",
            "yabadabadoo",
        ]

    @staticmethod
    def test_extract_payloads(jsjaws_class_instance):
        jsjaws_class_instance.malware_jail_payload_extraction_dir = path.join(
            jsjaws_class_instance.working_directory, "payload/"
        )
        jsjaws_class_instance.malware_jail_urls_json_path = path.join(
            jsjaws_class_instance.malware_jail_payload_extraction_dir, "urls.json"
        )
        jsjaws_class_instance.extracted_wscript_batch = "extracted_wscript.bat"
        jsjaws_class_instance.extracted_wscript_batch_path = path.join(
            jsjaws_class_instance.malware_jail_payload_extraction_dir, jsjaws_class_instance.extracted_wscript_batch
        )
        jsjaws_class_instance.boxjs_output_dir = path.join(jsjaws_class_instance.working_directory, "blah.results")
        jsjaws_class_instance.boxjs_snippets = path.join(jsjaws_class_instance.boxjs_output_dir, "snippets.json")
        mkdir(jsjaws_class_instance.boxjs_output_dir)
        mkdir(jsjaws_class_instance.malware_jail_payload_extraction_dir)
        jsjaws_class_instance.config["max_payloads_extracted"] = 1

        # Zero bytes file
        with open(f"{jsjaws_class_instance.malware_jail_payload_extraction_dir}/blah1.txt", "a+") as f:
            pass

        # urls_json_path file
        with open(jsjaws_class_instance.malware_jail_urls_json_path, "a+") as f:
            f.write("blah")

        # extracted_wscript_path file
        with open(jsjaws_class_instance.extracted_wscript_batch_path, "a+") as f:
            f.write("blah")

        # valid file 1
        valid_file_name1 = "zlah2.txt"
        valid_file_path1 = f"{jsjaws_class_instance.malware_jail_payload_extraction_dir}{valid_file_name1}"
        with open(valid_file_path1, "w") as f:
            f.write("blah2")

        # valid file 2
        valid_file_name2 = "zlah3.txt"
        valid_file_path2 = f"{jsjaws_class_instance.malware_jail_payload_extraction_dir}{valid_file_name2}"
        with open(valid_file_path2, "w") as f:
            f.write("blah3")

        # Box.js Snippets
        with open(jsjaws_class_instance.boxjs_snippets, "w") as f:
            f.write('{"yaba": []}')

        jsjaws_class_instance.artifact_list = []
        jsjaws_class_instance.boxjs_iocs = "IOC.json"
        jsjaws_class_instance.boxjs_resources = "resources.json"
        jsjaws_class_instance.boxjs_snippets = "snippets.json"
        jsjaws_class_instance.boxjs_analysis_log = "analysis.log"
        jsjaws_class_instance.boxjs_urls_json_path = "urls.json"
        jsjaws_class_instance._extract_payloads("blah", False)
        assert jsjaws_class_instance.artifact_list[0] == {
            "name": valid_file_name1,
            "path": valid_file_path1,
            "description": "Extracted Payload",
            "to_be_extracted": True,
        }

    @staticmethod
    def test_extract_urls(jsjaws_class_instance):
        jsjaws_class_instance.malware_jail_payload_extraction_dir = path.join(
            jsjaws_class_instance.working_directory, "payload/"
        )
        jsjaws_class_instance.malware_jail_urls_json_path = path.join(
            jsjaws_class_instance.malware_jail_payload_extraction_dir, "urls.json"
        )
        jsjaws_class_instance.boxjs_output_dir = path.join(jsjaws_class_instance.working_directory, "blah.results")
        jsjaws_class_instance.boxjs_iocs = path.join(jsjaws_class_instance.boxjs_output_dir, "IOC.json")
        mkdir(jsjaws_class_instance.boxjs_output_dir)
        mkdir(jsjaws_class_instance.malware_jail_payload_extraction_dir)
        body = [
            {"url": "http://blah.ca/blah.exe"},
            {"url": "http://1.1.1.1/blah.exe"},
            {"url": "blahblahblah"},
        ]
        with open(jsjaws_class_instance.malware_jail_urls_json_path, "w") as f:
            f.write(dumps(body))
        with open(jsjaws_class_instance.boxjs_iocs, "w") as f:
            val = [{"type": "UrlFetch", "value": {"url": url["url"]}} for url in body]
            val.append(
                {
                    "type": "UrlFetch",
                    "value": {"url": "http://definitely-a-url.ca", "method": "blah", "headers": "blah"},
                }
            )
            contents = dumps(val)
            f.write(contents)
        result = Result()
        jsjaws_class_instance._extract_urls(result)
        body.append({"url": "http://definitely-a-url.ca", "method": "blah", "request_headers": "blah"})
        correct_res_sec = ResultSection(
            "URLs",
            body_format=BODY_FORMAT.TABLE,
            body=dumps(body),
            tags={
                "network.dynamic.domain": ["blah.ca", "definitely-a-url.ca"],
                "network.dynamic.uri": [
                    "http://blah.ca/blah.exe",
                    "http://1.1.1.1/blah.exe",
                    "http://definitely-a-url.ca",
                ],
                "network.dynamic.ip": ["1.1.1.1"],
                "network.dynamic.uri_path": ["/blah.exe"],
                "file.string.extracted": ["blahblahblah"],
            },
        )
        correct_res_sec.set_heuristic(1)
        assert check_section_equality(result.sections[0], correct_res_sec)

        # Code Coverage
        remove(jsjaws_class_instance.malware_jail_urls_json_path)
        remove(jsjaws_class_instance.boxjs_iocs)
        jsjaws_class_instance._extract_urls(result)

    @staticmethod
    def test_extract_supplementary(jsjaws_class_instance):
        jsjaws_class_instance.malware_jail_sandbox_env_dir = path.join(
            jsjaws_class_instance.working_directory, "sandbox_env"
        )
        jsjaws_class_instance.malware_jail_sandbox_env_dump = "sandbox_dump.json"
        jsjaws_class_instance.malware_jail_sandbox_env_dir = path.join(
            jsjaws_class_instance.working_directory, "sandbox_env"
        )
        jsjaws_class_instance.malware_jail_sandbox_env_dump_path = path.join(
            jsjaws_class_instance.malware_jail_sandbox_env_dir, jsjaws_class_instance.malware_jail_sandbox_env_dump
        )
        jsjaws_class_instance.malware_jail_output = "output.txt"
        jsjaws_class_instance.malware_jail_output_path = path.join(
            jsjaws_class_instance.working_directory, jsjaws_class_instance.malware_jail_output
        )
        jsjaws_class_instance.boxjs_output_dir = path.join(jsjaws_class_instance.working_directory, "blah.results")
        jsjaws_class_instance.boxjs_analysis_log = path.join(jsjaws_class_instance.boxjs_output_dir, "analysis.log")

        mkdir(jsjaws_class_instance.boxjs_output_dir)
        mkdir(jsjaws_class_instance.malware_jail_sandbox_env_dir)
        jsjaws_class_instance.artifact_list = []
        output = ["blah"]
        with open(jsjaws_class_instance.malware_jail_sandbox_env_dump_path, "w") as f:
            f.write("blah")
        with open(jsjaws_class_instance.boxjs_analysis_log, "w") as f:
            f.write("blah")
        jsjaws_class_instance._extract_supplementary(output)
        assert jsjaws_class_instance.artifact_list[0] == {
            "name": jsjaws_class_instance.malware_jail_sandbox_env_dump,
            "path": jsjaws_class_instance.malware_jail_sandbox_env_dump_path,
            "description": "Sandbox Environment Details",
            "to_be_extracted": False,
        }
        assert jsjaws_class_instance.artifact_list[1] == {
            "name": jsjaws_class_instance.malware_jail_output,
            "path": jsjaws_class_instance.malware_jail_output_path,
            "description": "Malware Jail Output",
            "to_be_extracted": False,
        }
        assert jsjaws_class_instance.artifact_list[2] == {
            "name": "boxjs_analysis_log.log",
            "path": jsjaws_class_instance.boxjs_analysis_log,
            "description": "Box.js Output",
            "to_be_extracted": False,
        }

    @staticmethod
    def test_run_signatures(jsjaws_class_instance):
        output = ["blah", "SaveToFile"]
        result = Result()
        correct_section = ResultSection("Signatures")
        correct_subsection = ResultSection(
            "Signature: SaveToFile", body="JavaScript writes data to disk", parent=correct_section
        )
        correct_subsection.set_heuristic(3)
        correct_subsection.heuristic.add_signature_id("save_to_file", score=10)
        jsjaws_class_instance._run_signatures(output, result)
        jsjaws_class_instance._run_signatures(output, result, display_iocs=True)
        assert check_section_equality(result.sections[0], correct_section)
        correct_subsection.add_line("\t\tSaveToFile")
        assert check_section_equality(result.sections[1], correct_section)

    @staticmethod
    def test_process_signature():
        # NOTE that this method is tested in test_run_signatures
        assert True

    @staticmethod
    def test_extract_boxjs_iocs(jsjaws_class_instance):
        jsjaws_class_instance.malware_jail_payload_extraction_dir = path.join(
            jsjaws_class_instance.working_directory, "payload/"
        )
        jsjaws_class_instance.boxjs_batch = "boxjs_cmds.bat"
        jsjaws_class_instance.boxjs_batch_path = path.join(
            jsjaws_class_instance.malware_jail_payload_extraction_dir, jsjaws_class_instance.boxjs_batch
        )
        jsjaws_class_instance.boxjs_ps1 = "boxjs_cmds.ps1"
        jsjaws_class_instance.boxjs_ps1_path = path.join(
            jsjaws_class_instance.malware_jail_payload_extraction_dir, jsjaws_class_instance.boxjs_batch
        )
        jsjaws_class_instance.boxjs_output_dir = path.join(jsjaws_class_instance.working_directory, "blah.result")
        jsjaws_class_instance.boxjs_iocs = path.join(jsjaws_class_instance.boxjs_output_dir, "IOC.json")
        jsjaws_class_instance.artifact_list = []
        mkdir(jsjaws_class_instance.boxjs_output_dir)
        mkdir(jsjaws_class_instance.malware_jail_payload_extraction_dir)
        cmd = "blah http://blah.ca"
        file = "blah.txt"
        body = [
            {"type": "Run", "value": {"command": cmd}},
            {"type": "FileWrite", "value": {"file": file}},
            {"type": "FileRead", "value": {"file": file}},
        ]
        with open(jsjaws_class_instance.boxjs_iocs, "w") as f:
            f.write(dumps(body))
        correct_res_sec = ResultSection("IOCs extracted by Box.js")
        correct_res_sec.set_heuristic(2)
        cmd_res_sec = ResultSection("The script ran the following commands", parent=correct_res_sec)
        cmd_res_sec.add_lines([cmd])
        cmd_res_sec.add_tag("dynamic.process.command_line", cmd)
        cmd_table = ResultTableSection("IOCs found in command lines", parent=cmd_res_sec)
        table_data = [{"ioc_type": "domain", "ioc": "blah.ca"}, {"ioc_type": "uri", "ioc": "http://blah.ca"}]
        [cmd_table.add_row(TableRow(**item)) for item in table_data]
        cmd_table.add_tag("network.static.domain", "blah.ca")
        cmd_table.add_tag("network.static.uri", "http://blah.ca")
        cmd_table.set_heuristic(2)
        write_res_sec = ResultSection("The script wrote the following files", parent=correct_res_sec)
        write_res_sec.add_lines(["blah.txt"])
        write_res_sec.add_tag("dynamic.process.file_name", file)
        read_res_sec = ResultSection("The script read the following files", parent=correct_res_sec)
        read_res_sec.add_lines(["blah.txt"])
        read_res_sec.add_tag("dynamic.process.file_name", file)
        res = Result()
        jsjaws_class_instance._extract_boxjs_iocs(res)
        assert check_section_equality(res.sections[0], correct_res_sec)
        assert jsjaws_class_instance.artifact_list[0] == {
            "name": "boxjs_cmds.bat",
            "path": jsjaws_class_instance.boxjs_batch_path,
            "description": "Boxjs batch file",
            "to_be_extracted": True,
        }

    @staticmethod
    def test_flag_jsxray_iocs(jsjaws_class_instance, dummy_request_class_instance):
        output = {
            "warnings": [
                {"kind": "blah", "value": "blah"},
                {"kind": "unsafe-stmt", "value": "blah"},
                {"kind": "encoded-literal", "value": "blah"},
                {"kind": "obfuscated-code", "value": "blah"},
            ]
        }
        dummy_request_class_instance.result = Result()
        correct_res_sec = ResultSection(
            "JS-X-Ray IOCs Detected",
            body="\t\tblah:blah\n\t\tAn unsafe statement was found: blah\n\t\tAn encoded literal was "
            "found: blah\n\t\tObfuscated code was found that was obfuscated by: "
            "blah",
            tags={"file.string.extracted": ["blah"]},
        )
        correct_res_sec.set_heuristic(2)
        jsjaws_class_instance._flag_jsxray_iocs(output, dummy_request_class_instance)
        assert check_section_equality(dummy_request_class_instance.result.sections[0], correct_res_sec)

    @staticmethod
    def test_extract_malware_jail_iocs(jsjaws_class_instance):
        correct_res_sec = ResultTableSection("MalwareJail extracted the following IOCs")
        correct_res_sec.set_heuristic(2)
        correct_res_sec.add_tag("network.static.domain", "blah.com")
        correct_res_sec.add_tag("network.static.uri", "https://blah.com/blah.exe")
        correct_res_sec.add_tag("network.static.uri_path", "/blah.exe")
        table_data = [
            {"ioc_type": "domain", "ioc": "blah.com"},
            {"ioc_type": "uri", "ioc": "https://blah.com/blah.exe"},
            {"ioc_type": "uri_path", "ioc": "/blah.exe"},
        ]
        [correct_res_sec.add_row(TableRow(**item)) for item in table_data]
        # Generate a fake Request object with a single attribute
        request = type("Request", (object,), {"result": Result()})
        output = ["29 Jun 08:24:36 - https://blah.com/blah.exe"]
        jsjaws_class_instance._extract_malware_jail_iocs(output, request)
        assert check_section_equality(request.result.sections[0], correct_res_sec)

    @staticmethod
    def test_extract_filtered_code(jsjaws_class_instance, dummy_get_response_class, mocker):
        # Note that this is usually for Gootloader, and they always have more than 10 lines of evil code
        evil_string = "XMLHttpRequest('http://evil.com');\n"
        fake_response_text = "/*!\n * jQuery JavaScript Library v1.11.3\n * http://jquery.com/\n *\n * Includes Sizzle.js\n * http://sizzlejs.com/\n *\n * Copyright 2005, 2014 jQuery Foundation, Inc. and other contributors\n * Released under the MIT license\n * http://jquery.org/license\n *\n * Date: 2015-04-28T16:19Z\n */"
        mocker.patch("jsjaws.get", return_value=dummy_get_response_class(fake_response_text))
        file_contents = f"/*!\n * jQuery JavaScript Library v1.11.3\n * http://jquery.com/\n *\n * Includes Sizzle.js\n * http://sizzlejs.com/\n *\n * Copyright 2005, 2014 jQuery Foundation, Inc. and other contributors\n * Released under the MIT license\n{evil_string*11} * http://jquery.org/license\n *\n * Date: 2015-04-28T16:19Z\n */".encode()
        jsjaws_class_instance.artifact_list = []
        file_path, new_file_contents, lib_path = jsjaws_class_instance._extract_filtered_code(file_contents)

        assert path.exists(file_path)
        assert new_file_contents == evil_string.encode() * 11
        assert lib_path == "https://code.jquery.com/jquery-1.11.3.js"
        remove(file_path)

    @staticmethod
    @pytest.mark.parametrize(
        "line_1, line_2, expected_result",
        [
            ("blah", "blah", True),
            ("blah", "blahblah", False),
            ("blah", "//blah", True),
            ("//blah", "blah", True),
            ("\tblah", "blah", True),
            ("//\tblah", "blah", True),
        ],
    )
    def test_compare_lines(line_1, line_2, expected_result, jsjaws_class_instance):
        assert jsjaws_class_instance._compare_lines(line_1, line_2) == expected_result


class TestSignature:
    @staticmethod
    def test_init():
        default_sig = Signature()
        assert default_sig.heuristic_id is None
        assert default_sig.name is None
        assert default_sig.description is None
        assert default_sig.ttp == []
        assert default_sig.families == []
        assert default_sig.indicators == []
        assert default_sig.severity == 0
        assert default_sig.safelist == []
        assert default_sig.marks == list()

        loaded_sig = Signature(
            heuristic_id=1,
            name="blah",
            description="blah",
            ttp=["blah"],
            families=["blah"],
            indicators=["blah"],
            severity=1,
            safelist=["yabadabadoo"],
        )
        assert loaded_sig.heuristic_id == 1
        assert loaded_sig.name == "blah"
        assert loaded_sig.description == "blah"
        assert loaded_sig.ttp == ["blah"]
        assert loaded_sig.families == ["blah"]
        assert loaded_sig.indicators == ["blah"]
        assert loaded_sig.severity == 1
        assert loaded_sig.safelist == ["yabadabadoo"]
        assert loaded_sig.marks == list()

    @staticmethod
    @pytest.mark.parametrize(
        "indicators, safelist, output, match_all, expected_marks",
        [
            (None, [], [], False, list()),
            (None, [], ["blah"], False, list()),
            (None, [], ["blah - blah"], False, list()),
            (["yabadabadoo"], [], ["blah"], False, list()),
            (["blah"], [], ["blah"], False, ["blah"]),
            (["blah"], [], ["blah"], True, ["blah"]),
            (["blah"], ["yabadabadoo"], ["blah"], True, ["blah"]),
            (["blah", "blahblah"], ["yabadabadoo"], ["blah"], True, list()),
            (["blah"], ["yabadabadoo"], ["yabadabadoo"], True, list()),
        ],
    )
    def test_check_indicators_in_list(indicators, safelist, output, match_all, expected_marks):
        sig = Signature(indicators=indicators, safelist=safelist)
        sig.check_indicators_in_list(output, match_all)
        assert sig.marks == expected_marks

    @staticmethod
    @pytest.mark.parametrize(
        "regex, string, expected_output",
        [
            (r"", "", [""]),
            (r"nope", "yup", []),
            (r"daba", "yabadabadoo", ["daba"]),
        ],
    )
    def test_check_regex(regex, string, expected_output):
        assert Signature.check_regex(regex, string) == expected_output

    @staticmethod
    def test_process_output():
        sig = Signature()
        with pytest.raises(NotImplementedError):
            sig.process_output([])

    @staticmethod
    def test_add_mark():
        sig = Signature()
        sig.add_mark("")
        sig.add_mark(None)
        sig.add_mark(0)
        assert sig.marks == list()

        sig.add_mark("blah")
        assert sig.marks == ["blah"]

    @staticmethod
    @pytest.mark.parametrize(
        "indicators, safelist, output, expected_marks",
        [
            (None, [], [], list()),
            (None, [], ["blah"], list()),
            (None, [], ["blah - blah"], list()),
            # 1 any indicator that will match
            ([{"method": "any", "indicators": ["blah"]}], [], ["blah"], ["blah"]),
            # 1 all indicator that will match
            ([{"method": "all", "indicators": ["blah"]}], [], ["blah"], ["blah"]),
            # 1 any indicator that will match, safelisted item
            ([{"method": "any", "indicators": ["blah"]}], ["blah"], ["blah"], list()),
            # 1 all indicator that will match, safelisted item
            ([{"method": "all", "indicators": ["blah"]}], ["blah"], ["blah"], list()),
            # 1 any indicator that will not match
            ([{"method": "any", "indicators": ["yabadabadoo"]}], [], ["blah"], list()),
            # 1 all indicator that will not match
            ([{"method": "all", "indicators": ["yabadabadoo"]}], [], ["blah"], list()),
            # 2 any indicators, only one matches, therefore no marks
            (
                [{"method": "any", "indicators": ["blah"]}, {"method": "any", "indicators": ["blahblah"]}],
                [],
                ["blah"],
                list(),
            ),
            # 2 all indicators, only one matches, therefore no marks
            (
                [{"method": "all", "indicators": ["blah"]}, {"method": "any", "indicators": ["blahblah"]}],
                [],
                ["blah"],
                list(),
            ),
            # 2 any indicators, both match, one mark
            (
                [{"method": "any", "indicators": ["blah"]}, {"method": "any", "indicators": ["blahblah"]}],
                [],
                ["blah blahblah"],
                ["blah blahblah"],
            ),
            # 2 all indicators, both match, one mark
            (
                [{"method": "all", "indicators": ["blah"]}, {"method": "all", "indicators": ["blahblah"]}],
                [],
                ["blah blahblah"],
                ["blah blahblah"],
            ),
            # 1 any indicator with multiple indicators, which matches on multiple lines, therefore multiple marks
            (
                [{"method": "any", "indicators": ["blah", "yabadabadoo"]}],
                [],
                ["blah", "yabadabadoo", "abc123"],
                ["blah", "yabadabadoo"],
            ),
            # 1 all indicator with multiple indicators, which doesn't match on multiple lines, therefore no marks
            ([{"method": "all", "indicators": ["blah", "yabadabadoo"]}], [], ["blah", "yabadabadoo", "abc123"], list()),
            # 1 all indicator with multiple indicators, which match on single line, therefore one mark
            (
                [{"method": "all", "indicators": ["blah", "yabadabadoo"]}],
                [],
                ["blah yabadabadoo", "yabadabadoo", "abc123"],
                ["blah yabadabadoo"],
            ),
            # 2 all indicators with multiple indicators, which match on single line, therefore one mark
            (
                [
                    {"method": "all", "indicators": ["blah", "yabadabadoo"]},
                    {"method": "all", "indicators": ["halb", "oodabadabay"]},
                ],
                [],
                ["blah yabadabadoo oodabadabay halb", "abc123"],
                ["blah yabadabadoo oodabadabay halb"],
            ),
            # 1 any indicator with multiple indicators, 1 all indicator with multiple indicators, which match on single line, therefore one mark
            (
                [{"method": "any", "indicators": ["abc", "def"]}, {"method": "all", "indicators": ["ghi", "jkl"]}],
                [],
                ["abcdef", "abcghi", "abcghijkl"],
                ["abcghijkl"],
            ),
            # 2 any indicator with multiple indicators, 2 all indicator with multiple indicators, which match on single line, therefore one mark
            (
                [
                    {"method": "any", "indicators": ["abc", "def"]},
                    {"method": "all", "indicators": ["ghi", "jkl"]},
                    {"method": "any", "indicators": ["mno", "pqr"]},
                    {"method": "all", "indicators": ["stu", "vwx"]},
                ],
                [],
                ["abcdef", "abcghi", "abcghijkl", "abcghijklpqrstuvwx"],
                ["abcghijklpqrstuvwx"],
            ),
        ],
    )
    def test_check_multiple_indicators_in_list(indicators, safelist, output, expected_marks):
        sig = Signature(safelist=safelist)
        sig.check_multiple_indicators_in_list(output, indicators)
        assert sig.marks == expected_marks
