import os
import shutil

import pytest

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


def check_section_equality(this, that) -> bool:
    # Recursive method to check equality of result section and nested sections

    # Heuristics also need their own equality checks
    if this.heuristic and that.heuristic:
        result_heuristic_equality = (
            this.heuristic.attack_ids == that.heuristic.attack_ids
            and this.heuristic.frequency == that.heuristic.frequency
            and this.heuristic.heur_id == that.heuristic.heur_id
            and this.heuristic.score == that.heuristic.score
            and this.heuristic.score_map == that.heuristic.score_map
            and this.heuristic.signatures == that.heuristic.signatures
        )

        if not result_heuristic_equality:
            print("The heuristics are not equal:")
            if this.heuristic.attack_ids != that.heuristic.attack_ids:
                print("The attack_ids are different:")
                print(f"{this.heuristic.attack_ids}")
                print(f"{that.heuristic.attack_ids}")
            if this.heuristic.frequency != that.heuristic.frequency:
                print("The frequencies are different:")
                print(f"{this.heuristic.frequency}")
                print(f"{that.heuristic.frequency}")
            if this.heuristic.heur_id != that.heuristic.heur_id:
                print("The heur_ids are different:")
                print(f"{this.heuristic.heur_id}")
                print(f"{that.heuristic.heur_id}")
            if this.heuristic.score != that.heuristic.score:
                print("The scores are different:")
                print(f"{this.heuristic.score}")
                print(f"{that.heuristic.score}")
            if this.heuristic.score_map != that.heuristic.score_map:
                print("The score_maps are different:")
                print(f"{this.heuristic.score_map}")
                print(f"{that.heuristic.score_map}")
            if this.heuristic.signatures != that.heuristic.signatures:
                print("The signatures are different:")
                print(f"{this.heuristic.signatures}")
                print(f"{that.heuristic.signatures}")

    elif not this.heuristic and not that.heuristic:
        result_heuristic_equality = True
    else:
        print("The heuristics are not equal:")
        if this.heuristic:
            print(f"{this.heuristic.__dict__}")
        else:
            print("this.heuristic is None")
        if that.heuristic:
            print(f"{that.heuristic.__dict__}")
        else:
            print("that.heuristic is None")
        result_heuristic_equality = False

    # Assuming we are given the "root section" at all times, it is safe to say that we don't need to confirm parent
    current_section_equality = (
        result_heuristic_equality
        and this.body == that.body
        and this.body_format == that.body_format
        and this.classification == that.classification
        and this.depth == that.depth
        and len(this.subsections) == len(that.subsections)
        and this.title_text == that.title_text
        and this.tags == that.tags
        and this.auto_collapse == that.auto_collapse
    )

    if not current_section_equality:
        print("The current sections are not equal:")
        if not result_heuristic_equality:
            print("The result heuristics are not equal")
        if this.body != that.body:
            print("The bodies are different:")
            print(f"{this.body}")
            print(f"{that.body}")
        if this.body_format != that.body_format:
            print("The body formats are different:")
            print(f"{this.body_format}")
            print(f"{that.body_format}")
        if this.classification != that.classification:
            print("The classifications are different:")
            print(f"{this.classifications}")
            print(f"{that.classifications}")
        if this.depth != that.depth:
            print("The depths are different:")
            print(f"{this.depths}")
            print(f"{that.depths}")
        if len(this.subsections) != len(that.subsections):
            print("The number of subsections are different:")
            print(f"{len(this.subsections)}")
            print(f"{len(that.subsections)}")
        if this.title_text != that.title_text:
            print("The title texts are different:")
            print(f"{this.title_text}")
            print(f"{that.title_text}")
        if this.tags != that.tags:
            print("The tags are different:")
            print(f"{this.tags}")
            print(f"{that.tags}")
        if this.auto_collapse != that.auto_collapse:
            print("The auto_collapse settings are different:")
            print(f"{this.auto_collapse}")
            print(f"{that.auto_collapse}")
        return False

    for index, subsection in enumerate(this.subsections):
        subsection_equality = check_section_equality(subsection, that.subsections[index])
        if not subsection_equality:
            return False

    return True


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
def dummy_request_class_instance():
    class DummyRequest():
        def __init__(self):
            super(DummyRequest, self).__init__()
            self.temp_submission_data = {}
            self.result = None

    yield DummyRequest()


@pytest.fixture
def jsjaws_class_instance():
    create_tmp_manifest()
    try:
        from jsjaws import JsJaws

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
        from assemblyline_v4_service.common.balbuzard.patterns import PatternMatch

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
        assert jsjaws_class_instance.extracted_wscript is None
        assert jsjaws_class_instance.extracted_wscript_path is None
        assert jsjaws_class_instance.malware_jail_output is None
        assert jsjaws_class_instance.malware_jail_output_path is None
        assert jsjaws_class_instance.extracted_doc_writes is None
        assert jsjaws_class_instance.extracted_doc_writes_path is None
        assert jsjaws_class_instance.boxjs_output_dir is None
        assert jsjaws_class_instance.boxjs_iocs is None
        assert jsjaws_class_instance.boxjs_resources is None
        assert jsjaws_class_instance.boxjs_analysis_log is None
        assert jsjaws_class_instance.boxjs_snippets is None

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
    def test_execute(sample, jsjaws_class_instance, dummy_completed_process_instance, mocker):
        from os import mkdir, path
        from subprocess import TimeoutExpired

        from assemblyline.odm.messages.task import Task as ServiceTask
        from assemblyline_v4_service.common.dynamic_service_helper import (
            OntologyResults,
        )
        from assemblyline_v4_service.common.request import ServiceRequest
        from assemblyline_v4_service.common.result import ResultSection
        from assemblyline_v4_service.common.task import Task

        mocker.patch.object(jsjaws_class_instance, "_run_signatures")
        mocker.patch.object(jsjaws_class_instance, "_extract_boxjs_iocs")
        mocker.patch.object(jsjaws_class_instance, "_extract_wscript")
        mocker.patch.object(jsjaws_class_instance, "_extract_doc_writes")
        mocker.patch.object(jsjaws_class_instance, "_extract_payloads")
        mocker.patch.object(jsjaws_class_instance, "_extract_urls")
        mocker.patch.object(jsjaws_class_instance, "_extract_supplementary")
        mocker.patch.object(jsjaws_class_instance, "_flag_jsxray_iocs")
        mocker.patch.object(OntologyResults, "handle_artifacts")
        mocker.patch("jsjaws.Popen", return_value=dummy_completed_process_instance)

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
            "static_analysis_only": False,
            "enable_synchrony": False,
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
        assert jsjaws_class_instance.wscript_only_config == path.join(root_dir, "tools/malwarejail/config_wscript_only.json")
        assert jsjaws_class_instance.extracted_wscript == "extracted_wscript.bat"
        assert jsjaws_class_instance.extracted_wscript_path == path.join(
            jsjaws_class_instance.malware_jail_payload_extraction_dir, jsjaws_class_instance.extracted_wscript
        )
        assert jsjaws_class_instance.malware_jail_output == "output.txt"
        assert jsjaws_class_instance.malware_jail_output_path == path.join(
            jsjaws_class_instance.working_directory, jsjaws_class_instance.malware_jail_output
        )
        assert jsjaws_class_instance.extracted_doc_writes == "document_writes.html"
        assert jsjaws_class_instance.extracted_doc_writes_path == path.join(
            jsjaws_class_instance.malware_jail_payload_extraction_dir, jsjaws_class_instance.extracted_doc_writes
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
        mocker.patch("jsjaws.Popen", side_effect=TimeoutExpired("blah", 1))
        jsjaws_class_instance.execute(service_request)

    @staticmethod
    def test_extract_wscript(jsjaws_class_instance, mocker):
        from os import mkdir
        from os.path import exists, join

        from assemblyline_v4_service.common.result import Result

        jsjaws_class_instance.payload_extraction_dir = join(jsjaws_class_instance.working_directory, "payload/")
        jsjaws_class_instance.extracted_wscript = "extracted_wscript.bat"
        jsjaws_class_instance.extracted_wscript_path = join(
            jsjaws_class_instance.payload_extraction_dir, jsjaws_class_instance.extracted_wscript
        )
        mkdir(jsjaws_class_instance.payload_extraction_dir)
        mocker.patch("jsjaws.extract_iocs_from_text_blob")
        output = ["WScript.Shell[4].Run(super evil script, 0, undefined)"]
        res = Result()
        jsjaws_class_instance.artifact_list = []
        jsjaws_class_instance._extract_wscript(output, res)
        assert exists(jsjaws_class_instance.extracted_wscript_path)
        assert jsjaws_class_instance.artifact_list[0] == {
            "name": jsjaws_class_instance.extracted_wscript,
            "path": jsjaws_class_instance.extracted_wscript_path,
            "description": "Extracted WScript",
            "to_be_extracted": True,
        }

    @staticmethod
    def test_extract_doc_writes_one_liners(jsjaws_class_instance, dummy_request_class_instance):
        # Single line example : 697b0e897a7d57e600a1020886f837469ffb87acc65f04c2ae424af50a311c7e
        # Multiple calls to document.write() (with multiline) example :
        # 4b19570cb328f4e47a44e04a74c94993225203260607f615a875cd58500c9abb
        from os import mkdir
        from os.path import exists, join

        jsjaws_class_instance.malware_jail_payload_extraction_dir = join(
            jsjaws_class_instance.working_directory, "payload/"
        )
        jsjaws_class_instance.extracted_doc_writes = "document_writes.html"
        jsjaws_class_instance.extracted_doc_writes_path = join(
            jsjaws_class_instance.malware_jail_payload_extraction_dir, jsjaws_class_instance.extracted_doc_writes
        )
        mkdir(jsjaws_class_instance.malware_jail_payload_extraction_dir)
        output = [
            "[2022-10-18T20:12:49.924Z] document[15].write(content) 0 bytes",
            "[2022-10-18T20:12:50.924Z] => 'write me!'",
            "[2022-10-18T20:12:51.924Z] => Something else",
            "[2022-10-18T20:12:52.924Z] document[15].write(content) 0 bytes",
            "[2022-10-18T20:12:53.924Z] => 'write me too!'",
            "[2022-10-18T20:12:52.924Z] document[15].write(content) 0 bytes",
            "[2022-10-18T20:12:53.924Z] => 'password?!'",
        ]
        jsjaws_class_instance.artifact_list = []
        jsjaws_class_instance._extract_doc_writes(output, dummy_request_class_instance)
        assert exists(jsjaws_class_instance.extracted_doc_writes_path)
        with open(jsjaws_class_instance.extracted_doc_writes_path, "r") as f:
            assert f.read() == "write me!\nwrite me too!\npassword?!"
        assert jsjaws_class_instance.artifact_list[0] == {
            "name": jsjaws_class_instance.extracted_doc_writes,
            "path": jsjaws_class_instance.extracted_doc_writes_path,
            "description": "DOM Writes",
            "to_be_extracted": True,
        }
        assert dummy_request_class_instance.temp_submission_data.get("passwords") == ['me', 'me!', 'password', 'password?!', 'too', 'too!', 'write']

    @staticmethod
    def test_extract_doc_writes_multiliner(jsjaws_class_instance, dummy_request_class_instance):
        # Multiple calls to document.write() (with multiline) example :
        # 4b19570cb328f4e47a44e04a74c94993225203260607f615a875cd58500c9abb
        from os import mkdir
        from os.path import exists, join

        jsjaws_class_instance.malware_jail_payload_extraction_dir = join(
            jsjaws_class_instance.working_directory, "payload/"
        )
        jsjaws_class_instance.extracted_doc_writes = "document_writes.html"
        jsjaws_class_instance.extracted_doc_writes_path = join(
            jsjaws_class_instance.malware_jail_payload_extraction_dir, jsjaws_class_instance.extracted_doc_writes
        )
        mkdir(jsjaws_class_instance.malware_jail_payload_extraction_dir)
        output = [
            "[2022-10-18T20:12:49.924Z] document[15].write(content) 0 bytes",
            "[2022-10-18T20:12:50.924Z] => '",
            "<html>",
            "password: yabadabadoo",
            "</html>'",
            "[2022-10-18T20:12:51.924Z] - Something else",
        ]
        jsjaws_class_instance.artifact_list = []
        jsjaws_class_instance._extract_doc_writes(output, dummy_request_class_instance)
        assert exists(jsjaws_class_instance.extracted_doc_writes_path)
        with open(jsjaws_class_instance.extracted_doc_writes_path, "r") as f:
            assert f.read() == "<html>\npassword: yabadabadoo\n</html>"
        assert jsjaws_class_instance.artifact_list[0] == {
            "name": jsjaws_class_instance.extracted_doc_writes,
            "path": jsjaws_class_instance.extracted_doc_writes_path,
            "description": "DOM Writes",
            "to_be_extracted": True,
        }
        assert dummy_request_class_instance.temp_submission_data.get("passwords") == [' yabadabadoo', '</html>', '<html>', 'html', 'password', 'password:', 'yabadabadoo']

    @staticmethod
    def test_extract_payloads(jsjaws_class_instance):
        from os import mkdir, path

        jsjaws_class_instance.malware_jail_payload_extraction_dir = path.join(
            jsjaws_class_instance.working_directory, "payload/"
        )
        jsjaws_class_instance.malware_jail_urls_json_path = path.join(
            jsjaws_class_instance.malware_jail_payload_extraction_dir, "urls.json"
        )
        jsjaws_class_instance.extracted_wscript = "extracted_wscript.bat"
        jsjaws_class_instance.extracted_wscript_path = path.join(
            jsjaws_class_instance.malware_jail_payload_extraction_dir, jsjaws_class_instance.extracted_wscript
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
        with open(jsjaws_class_instance.extracted_wscript_path, "a+") as f:
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
        jsjaws_class_instance._extract_payloads("blah", False)
        assert jsjaws_class_instance.artifact_list[0] == {
            "name": valid_file_name1,
            "path": valid_file_path1,
            "description": "Extracted Payload",
            "to_be_extracted": True,
        }

    @staticmethod
    def test_extract_urls(jsjaws_class_instance):
        from json import dumps
        from os import mkdir, path, remove

        from assemblyline_v4_service.common.result import (
            BODY_FORMAT,
            Result,
            ResultSection,
        )

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
                "network.dynamic.uri": [
                    "http://blah.ca/blah.exe",
                    "http://1.1.1.1/blah.exe",
                    "http://definitely-a-url.ca",
                ],
                "network.dynamic.domain": ["blah.ca", "blah.exe", "definitely-a-url.ca"],
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
        from os import mkdir, path

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
        from assemblyline_v4_service.common.result import Result, ResultSection

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
        from json import dumps
        from os import mkdir, path

        from assemblyline_v4_service.common.result import (
            Result,
            ResultSection,
            ResultTableSection,
            TableRow,
        )

        jsjaws_class_instance.boxjs_output_dir = path.join(jsjaws_class_instance.working_directory, "blah.result")
        jsjaws_class_instance.boxjs_iocs = path.join(jsjaws_class_instance.boxjs_output_dir, "IOC.json")
        jsjaws_class_instance.artifact_list = []
        mkdir(jsjaws_class_instance.boxjs_output_dir)
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
        cmd_table.add_tag("network.dynamic.domain", "blah.ca")
        cmd_table.add_tag("network.dynamic.uri", "http://blah.ca")
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
            "name": "cmd_0.txt",
            "path": path.join(jsjaws_class_instance.working_directory, "cmd_0.txt"),
            "description": "Command Extracted",
            "to_be_extracted": True,
        }

    @staticmethod
    def test_flag_jsxray_iocs(jsjaws_class_instance, dummy_request_class_instance):
        from assemblyline_v4_service.common.result import Result, ResultSection

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
            body="\t\tAn unsafe statement was found: blah\n\t\tAn encoded literal was "
            "found: blah\n\t\tObfuscated code was found that was obfuscated by: "
            "blah",
            tags={"file.string.extracted": ["blah"]},
        )
        correct_res_sec.set_heuristic(2)
        jsjaws_class_instance._flag_jsxray_iocs(output, dummy_request_class_instance)
        assert check_section_equality(dummy_request_class_instance.result.sections[0], correct_res_sec)

    @staticmethod
    def test_extract_malware_jail_iocs(jsjaws_class_instance):
        from assemblyline_v4_service.common.result import (
            Result,
            ResultTableSection,
            TableRow,
        )

        correct_res_sec = ResultTableSection("MalwareJail extracted the following IOCs")
        correct_res_sec.set_heuristic(2)
        correct_res_sec.add_tag("network.dynamic.domain", "blah.com")
        correct_res_sec.add_tag("network.dynamic.uri", "https://blah.com/blah.exe")
        correct_res_sec.add_tag("network.dynamic.uri_path", "/blah.exe")
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
        from os import path, remove

        from assemblyline_v4_service.common.result import Result, ResultSection

        evil_string = "XMLHttpRequest('http://evil.com');\n"
        fake_response_text = "/*!\n * jQuery JavaScript Library v1.11.3\n * http://jquery.com/\n *\n * Includes Sizzle.js\n * http://sizzlejs.com/\n *\n * Copyright 2005, 2014 jQuery Foundation, Inc. and other contributors\n * Released under the MIT license\n * http://jquery.org/license\n *\n * Date: 2015-04-28T16:19Z\n */"
        mocker.patch("jsjaws.get", return_value=dummy_get_response_class(fake_response_text))
        file_contents = f"/*!\n * jQuery JavaScript Library v1.11.3\n * http://jquery.com/\n *\n * Includes Sizzle.js\n * http://sizzlejs.com/\n *\n * Copyright 2005, 2014 jQuery Foundation, Inc. and other contributors\n * Released under the MIT license\n{evil_string} * http://jquery.org/license\n *\n * Date: 2015-04-28T16:19Z\n */"
        jsjaws_class_instance.filtered_lib = "filtered_lib.js"
        jsjaws_class_instance.filtered_lib_path = path.join("/tmp", jsjaws_class_instance.filtered_lib)
        jsjaws_class_instance.artifact_list = []
        res = Result()
        correct_res_sec = ResultSection(
            "Embedded code was found in common library",
            body=f"View extracted file {jsjaws_class_instance.filtered_lib} for details.",
        )
        correct_res_sec.set_heuristic(4)
        jsjaws_class_instance._extract_filtered_code(res, file_contents)

        assert path.exists(jsjaws_class_instance.filtered_lib_path)
        with open(jsjaws_class_instance.filtered_lib_path, "r") as f:
            val = f.read()
            assert val == evil_string
        assert jsjaws_class_instance.artifact_list[0] == {
            "name": jsjaws_class_instance.filtered_lib,
            "path": jsjaws_class_instance.filtered_lib_path,
            "description": "JavaScript embedded within common library",
            "to_be_extracted": True,
        }
        assert check_section_equality(res.sections[0], correct_res_sec)
        remove(jsjaws_class_instance.filtered_lib_path)

    @staticmethod
    @pytest.mark.parametrize("line_1, line_2, expected_result", [
        ("blah", "blah", True),
        ("blah", "blahblah", False),
        ("blah", "//blah", True),
        ("//blah", "blah", True),
        ("\tblah", "blah", True),
        ("//\tblah", "blah", True),
    ])
    def test_compare_lines(line_1, line_2, expected_result, jsjaws_class_instance):
        assert jsjaws_class_instance._compare_lines(line_1, line_2) == expected_result


class TestSignature:
    @staticmethod
    def test_init():
        from signatures.abstracts import Signature

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
        from signatures.abstracts import Signature

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
        from signatures.abstracts import Signature

        assert Signature.check_regex(regex, string) == expected_output

    @staticmethod
    def test_process_output():
        from signatures.abstracts import Signature

        sig = Signature()
        with pytest.raises(NotImplementedError):
            sig.process_output([])

    @staticmethod
    def test_add_mark():
        from signatures.abstracts import Signature

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
        from signatures.abstracts import Signature

        sig = Signature(safelist=safelist)
        sig.check_multiple_indicators_in_list(output, indicators)
        assert sig.marks == expected_marks
