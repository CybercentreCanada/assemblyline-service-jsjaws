import os
import pytest
import shutil

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
        service_name='jsjaws',
        service_config={},
        fileinfo=dict(
            magic='ASCII text, with no line terminators',
            md5='fda4e701258ba56f465e3636e60d36ec',
            mime='text/plain',
            sha1='af2c2618032c679333bebf745e75f9088748d737',
            sha256='dadc624d4454e10293dbd1b701b9ee9f99ef83b4cd07b695111d37eb95abcff8',
            size=19,
            type='unknown',
        ),
        filename='dadc624d4454e10293dbd1b701b9ee9f99ef83b4cd07b695111d37eb95abcff8',
        min_classification='TLP:WHITE',
        max_files=501,  # TODO: get the actual value
        ttl=3600,
    ),
]


def check_section_equality(this, that) -> bool:
    # Recursive method to check equality of result section and nested sections

    # Heuristics also need their own equality checks
    if this.heuristic and that.heuristic:
        heuristic_equality = this.heuristic.definition.attack_id == that.heuristic.definition.attack_id and \
                             this.heuristic.definition.classification == that.heuristic.definition.classification and \
                             this.heuristic.definition.description == that.heuristic.definition.description and \
                             this.heuristic.definition.filetype == that.heuristic.definition.filetype and \
                             this.heuristic.definition.heur_id == that.heuristic.definition.heur_id and \
                             this.heuristic.definition.id == that.heuristic.definition.id and \
                             this.heuristic.definition.max_score == that.heuristic.definition.max_score and \
                             this.heuristic.definition.name == that.heuristic.definition.name and \
                             this.heuristic.definition.score == that.heuristic.definition.score and \
                             this.heuristic.definition.signature_score_map == \
                             that.heuristic.definition.signature_score_map

        result_heuristic_equality = heuristic_equality and \
                                    this.heuristic.attack_ids == that.heuristic.attack_ids and \
                                    this.heuristic.frequency == that.heuristic.frequency and \
                                    this.heuristic.heur_id == that.heuristic.heur_id and \
                                    this.heuristic.score == that.heuristic.score and \
                                    this.heuristic.score_map == that.heuristic.score_map and \
                                    this.heuristic.signatures == that.heuristic.signatures

    elif not this.heuristic and not that.heuristic:
        result_heuristic_equality = True
    else:
        result_heuristic_equality = False

    # Assuming we are given the "root section" at all times, it is safe to say that we don't need to confirm parent
    current_section_equality = result_heuristic_equality and \
                               this.body == that.body and \
                               this.body_format == that.body_format and \
                               this.classification == that.classification and \
                               this.depth == that.depth and \
                               len(this.subsections) == len(that.subsections) and \
                               this.title_text == that.title_text and \
                               this.tags == that.tags

    if not current_section_equality:
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
            self.stdout = b"blah\nblah"
    yield DummyCompletedProcess()


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
        assert isinstance(jsjaws_class_instance.patterns, PatternMatch)
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
        from assemblyline_v4_service.common.task import Task
        from assemblyline_v4_service.common.dynamic_service_helper import SandboxOntology
        from assemblyline.odm.messages.task import Task as ServiceTask
        from assemblyline_v4_service.common.request import ServiceRequest
        from assemblyline_v4_service.common.result import ResultSection
        from json import loads
        from os import path, mkdir
        from subprocess import TimeoutExpired

        mocker.patch.object(jsjaws_class_instance, "_run_signatures")
        mocker.patch.object(jsjaws_class_instance, "_extract_boxjs_iocs")
        mocker.patch.object(jsjaws_class_instance, "_extract_wscript")
        mocker.patch.object(jsjaws_class_instance, "_extract_doc_writes")
        mocker.patch.object(jsjaws_class_instance, "_extract_payloads")
        mocker.patch.object(jsjaws_class_instance, "_extract_urls")
        mocker.patch.object(jsjaws_class_instance, "_extract_supplementary")
        mocker.patch.object(jsjaws_class_instance, "_flag_jsxray_iocs")
        mocker.patch.object(SandboxOntology, "handle_artifacts")
        mocker.patch("jsjaws.run", return_value=dummy_completed_process_instance)

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
            "display_iocs": False
        }
        jsjaws_class_instance._task = task
        service_request = ServiceRequest(task)

        jsjaws_class_instance.boxjs_output_dir = path.join(jsjaws_class_instance.working_directory, f"{service_request.sha256}.results")
        jsjaws_class_instance.boxjs_analysis_log = path.join(jsjaws_class_instance.boxjs_output_dir, "analysis.log")
        mkdir(jsjaws_class_instance.boxjs_output_dir)
        with open(jsjaws_class_instance.boxjs_analysis_log, "w") as f:
            f.write("blah\nblah\nblah")

        # Actually executing the sample
        jsjaws_class_instance.execute(service_request)

        assert jsjaws_class_instance.artifact_list == []
        assert jsjaws_class_instance.malware_jail_payload_extraction_dir == path.join(jsjaws_class_instance.working_directory, "payload/")
        assert jsjaws_class_instance.malware_jail_sandbox_env_dump == "sandbox_dump.json"
        assert jsjaws_class_instance.malware_jail_sandbox_env_dir == path.join(jsjaws_class_instance.working_directory, "sandbox_env")
        assert jsjaws_class_instance.malware_jail_sandbox_env_dump_path == path.join(jsjaws_class_instance.malware_jail_sandbox_env_dir, jsjaws_class_instance.malware_jail_sandbox_env_dump)
        root_dir = path.dirname(path.dirname(path.abspath(__file__)))
        assert jsjaws_class_instance.path_to_jailme_js == path.join(root_dir, "tools/jailme.js")
        assert jsjaws_class_instance.malware_jail_urls_json_path == path.join(jsjaws_class_instance.malware_jail_payload_extraction_dir, "urls.json")
        assert jsjaws_class_instance.wscript_only_config == path.join(root_dir, "tools/config_wscript_only.json")
        assert jsjaws_class_instance.extracted_wscript == "extracted_wscript.bat"
        assert jsjaws_class_instance.extracted_wscript_path == path.join(jsjaws_class_instance.malware_jail_payload_extraction_dir, jsjaws_class_instance.extracted_wscript)
        assert jsjaws_class_instance.malware_jail_output == "output.txt"
        assert jsjaws_class_instance.malware_jail_output_path == path.join(jsjaws_class_instance.working_directory, jsjaws_class_instance.malware_jail_output)
        assert jsjaws_class_instance.extracted_doc_writes == "document_writes.html"
        assert jsjaws_class_instance.extracted_doc_writes_path == path.join(jsjaws_class_instance.malware_jail_payload_extraction_dir, jsjaws_class_instance.extracted_doc_writes)

        assert path.exists(jsjaws_class_instance.malware_jail_payload_extraction_dir)
        assert path.exists(jsjaws_class_instance.malware_jail_sandbox_env_dir)

        # Get the result of execute() from the test method
        test_result = task.get_service_result()

        # Get the assumed "correct" result of the sample
        correct_result_path = os.path.join(TEST_DIR, "results", task.file_name + ".json")
        with open(correct_result_path, "r") as f:
            correct_result = loads(f.read())
        f.close()

        # Assert that the appropriate sections of the dict are equal

        # Avoiding unique items in the response
        test_result_response = test_result.pop("response")
        correct_result_response = correct_result.pop("response")
        assert test_result == correct_result

        # Comparing everything in the response except for the service_completed and the output.json supplementary
        test_result_response["milestones"].pop("service_completed")
        correct_result_response["milestones"].pop("service_completed")
        correct_result_response.pop("supplementary")
        test_result_response.pop("supplementary")
        correct_result_response.pop("service_context")
        test_result_response.pop("service_context")
        assert test_result_response == correct_result_response

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
        mocker.patch("jsjaws.run", side_effect=TimeoutExpired("blah", 1))
        jsjaws_class_instance.execute(service_request)

    @staticmethod
    def test_extract_wscript(jsjaws_class_instance, mocker):
        from os.path import exists, join
        from os import mkdir
        from assemblyline_v4_service.common.result import Result
        jsjaws_class_instance.payload_extraction_dir = join(jsjaws_class_instance.working_directory, "payload/")
        jsjaws_class_instance.extracted_wscript = "extracted_wscript.bat"
        jsjaws_class_instance.extracted_wscript_path = join(jsjaws_class_instance.payload_extraction_dir, jsjaws_class_instance.extracted_wscript)
        mkdir(jsjaws_class_instance.payload_extraction_dir)
        mocker.patch.object(jsjaws_class_instance, "_extract_iocs_from_text_blob")
        output = ["WScript.Shell[4].Run(super evil script, 0, undefined)"]
        res = Result()
        jsjaws_class_instance.artifact_list = []
        jsjaws_class_instance._extract_wscript(output, res)
        assert exists(jsjaws_class_instance.extracted_wscript_path)
        assert jsjaws_class_instance.artifact_list[0] == {
            "name": jsjaws_class_instance.extracted_wscript,
            "path": jsjaws_class_instance.extracted_wscript_path,
            "description": "Extracted WScript",
            "to_be_extracted": True
        }

    @staticmethod
    def test_extract_doc_writes(jsjaws_class_instance):
        from os.path import exists, join
        from os import mkdir
        jsjaws_class_instance.malware_jail_payload_extraction_dir = join(jsjaws_class_instance.working_directory, "payload/")
        jsjaws_class_instance.extracted_doc_writes = "document_writes.html"
        jsjaws_class_instance.extracted_doc_writes_path = join(jsjaws_class_instance.malware_jail_payload_extraction_dir,
                                                            jsjaws_class_instance.extracted_doc_writes)
        mkdir(jsjaws_class_instance.malware_jail_payload_extraction_dir)
        output = ["document[15].write(content)", "date time - => 'write me!'", "blah", "document[15].write(content)", "write me too!"]
        jsjaws_class_instance.artifact_list = []
        jsjaws_class_instance._extract_doc_writes(output)
        assert exists(jsjaws_class_instance.extracted_doc_writes_path)
        with open(jsjaws_class_instance.extracted_doc_writes_path, "r") as f:
            assert f.read() == "write me!\nwrite me too!\n"
        assert jsjaws_class_instance.artifact_list[0] == {
            "name": jsjaws_class_instance.extracted_doc_writes,
            "path": jsjaws_class_instance.extracted_doc_writes_path,
            "description": "DOM Writes",
            "to_be_extracted": True
        }

    @staticmethod
    def test_extract_payloads(jsjaws_class_instance):
        from os import mkdir, path
        jsjaws_class_instance.malware_jail_payload_extraction_dir = path.join(jsjaws_class_instance.working_directory, "payload/")
        jsjaws_class_instance.malware_jail_urls_json_path = path.join(jsjaws_class_instance.malware_jail_payload_extraction_dir, "urls.json")
        jsjaws_class_instance.extracted_wscript = "extracted_wscript.bat"
        jsjaws_class_instance.extracted_wscript_path = path.join(jsjaws_class_instance.malware_jail_payload_extraction_dir, jsjaws_class_instance.extracted_wscript)
        jsjaws_class_instance.boxjs_output_dir = path.join(jsjaws_class_instance.working_directory, f"blah.results")
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
            "to_be_extracted": True
        }

    @staticmethod
    def test_extract_urls(jsjaws_class_instance):
        from json import dumps
        from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT
        from os import mkdir, path, remove
        jsjaws_class_instance.malware_jail_payload_extraction_dir = path.join(jsjaws_class_instance.working_directory, "payload/")
        jsjaws_class_instance.malware_jail_urls_json_path = path.join(jsjaws_class_instance.malware_jail_payload_extraction_dir, "urls.json")
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
            val.append({"type": "UrlFetch", "value": {"url": "http://definitely-a-url.ca", "method": "blah", "headers": "blah"}})
            contents = dumps(val)
            f.write(contents)
        result = Result()
        jsjaws_class_instance._extract_urls(result)
        body.append({"url": "http://definitely-a-url.ca", "method": "blah", "request_headers": "blah"})
        correct_res_sec = ResultSection("URLs", body_format=BODY_FORMAT.TABLE, body=dumps(body),
                                        tags={
                                            "network.dynamic.uri": ["http://blah.ca/blah.exe", "http://1.1.1.1/blah.exe", "http://definitely-a-url.ca"],
                                            "network.dynamic.domain": ["blah.ca", "blah.exe", "definitely-a-url.ca"],
                                            "network.dynamic.ip": ["1.1.1.1"],
                                            "network.dynamic.uri_path": ["/blah.exe"],
                                            "file.string.extracted": ["blahblahblah"]
                                        })
        correct_res_sec.set_heuristic(1)
        assert check_section_equality(result.sections[0], correct_res_sec)

        # Code Coverage
        remove(jsjaws_class_instance.malware_jail_urls_json_path)
        remove(jsjaws_class_instance.boxjs_iocs)
        jsjaws_class_instance._extract_urls(result)

    @staticmethod
    def test_extract_supplementary(jsjaws_class_instance):
        from os import mkdir, path
        jsjaws_class_instance.malware_jail_sandbox_env_dir = path.join(jsjaws_class_instance.working_directory, "sandbox_env")
        jsjaws_class_instance.malware_jail_sandbox_env_dump = "sandbox_dump.json"
        jsjaws_class_instance.malware_jail_sandbox_env_dir = path.join(jsjaws_class_instance.working_directory, "sandbox_env")
        jsjaws_class_instance.malware_jail_sandbox_env_dump_path = path.join(jsjaws_class_instance.malware_jail_sandbox_env_dir, jsjaws_class_instance.malware_jail_sandbox_env_dump)
        jsjaws_class_instance.malware_jail_output = "output.txt"
        jsjaws_class_instance.malware_jail_output_path = path.join(jsjaws_class_instance.working_directory, jsjaws_class_instance.malware_jail_output)
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
            "to_be_extracted": False
        }
        assert jsjaws_class_instance.artifact_list[1] == {
            "name": jsjaws_class_instance.malware_jail_output,
            "path": jsjaws_class_instance.malware_jail_output_path,
            "description": "Malware Jail Output",
            "to_be_extracted": False
        }
        assert jsjaws_class_instance.artifact_list[2] == {
            "name": "boxjs_analysis_log.log",
            "path": jsjaws_class_instance.boxjs_analysis_log,
            "description": "Box.js Output",
            "to_be_extracted": False
        }

    @staticmethod
    @pytest.mark.parametrize(
        "blob, file_ext, correct_tags",
        [
            ("", "", {}),
            ("192.168.100.1", "", {'network.dynamic.ip': ['192.168.100.1']}),
            ("blah.ca", ".exe", {'network.dynamic.domain': ['blah.ca']}),
            ("https://blah.ca", ".exe", {'network.dynamic.domain': ['blah.ca'], 'network.dynamic.uri': ['https://blah.ca']}),
            ("https://blah.ca/blah", ".exe", {'network.dynamic.domain': ['blah.ca'], 'network.dynamic.uri': ['https://blah.ca/blah'], "network.dynamic.uri_path": ["/blah"]}),
            ("drive:\\\\path to\\\\microsoft office\\\\officeverion\\\\winword.exe", ".exe", {}),
            ("DRIVE:\\\\PATH TO\\\\MICROSOFT OFFICE\\\\OFFICEVERION\\\\WINWORD.EXE C:\\\\USERS\\\\BUDDY\\\\APPDATA\\\\LOCAL\\\\TEMP\\\\BLAH.DOC", ".exe", {}),
            ("DRIVE:\\\\PATH TO\\\\PYTHON27.EXE C:\\\\USERS\\\\BUDDY\\\\APPDATA\\\\LOCAL\\\\TEMP\\\\BLAH.py", ".py", {}),
            ("POST /some/thing/bad.exe HTTP/1.0\nUser-Agent: Mozilla\nHost: evil.ca\nAccept: */*\nContent-Type: application/octet-stream\nContent-Encoding: binary\n\nConnection: close", "", {"network.dynamic.domain": ["evil.ca"]}),
            ("evil.ca/some/thing/bad.exe", "", {"network.dynamic.domain": ["evil.ca"], "network.dynamic.uri": ["evil.ca/some/thing/bad.exe"], "network.dynamic.uri_path": ["/some/thing/bad.exe"]}),
            ("wscript.shell", "", {}),
            ("blah.ca", ".ca", {}),
            ("http://1.1.1.1/blah.exe", "", {'network.dynamic.ip': ['1.1.1.1'], 'network.dynamic.uri': ['http://1.1.1.1/blah.exe'], 'network.dynamic.uri_path': ['/blah.exe']}),
        ]
    )
    def test_extract_iocs_from_text_blob(blob, file_ext, correct_tags, jsjaws_class_instance):
        from assemblyline_v4_service.common.result import ResultSection
        test_result_section = ResultSection("blah")
        correct_result_section = ResultSection("blah", tags=correct_tags)
        if correct_tags:
            correct_result_section.set_heuristic(2)
        jsjaws_class_instance._extract_iocs_from_text_blob(blob, test_result_section, file_ext)
        assert check_section_equality(test_result_section, correct_result_section)

    @staticmethod
    def test_run_signatures(jsjaws_class_instance):
        from assemblyline_v4_service.common.result import Result, ResultSection
        output = ["blah", "SaveToFile"]
        result = Result()
        correct_section = ResultSection("Signatures")
        correct_subsection = ResultSection("Signature: SaveToFile", body="JavaScript writes data to disk", parent=correct_section)
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
        from os import path, mkdir
        from json import dumps
        from assemblyline_v4_service.common.result import Result, ResultSection
        jsjaws_class_instance.boxjs_output_dir = path.join(jsjaws_class_instance.working_directory, f"blah.result")
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
        cmd_res_sec.add_tag("network.dynamic.domain", "blah.ca")
        cmd_res_sec.add_tag("network.dynamic.uri", "http://blah.ca")
        cmd_res_sec.set_heuristic(2)
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
            "to_be_extracted": True
        }

    @staticmethod
    def test_flag_jsxray_iocs(jsjaws_class_instance):
        from assemblyline_v4_service.common.result import Result, ResultSection
        output = {"warnings": [
            {"kind": "blah", "value": "blah"},
            {"kind": "unsafe-stmt", "value": "blah"},
            {"kind": "encoded-literal", "value": "blah"},
            {"kind": "obfuscated-code", "value": "blah"},
        ]}
        res = Result()
        correct_res_sec = ResultSection("JS-X-Ray IOCs Detected",
                                        body="\t\tAn unsafe statement was found: blah\n\t\tAn encoded literal was "
                                             "found: blah\n\t\tObfuscated code was found that was obfuscated by: "
                                             "blah",
                                        tags={"file.string.extracted": ["blah"]})
        correct_res_sec.set_heuristic(2)
        jsjaws_class_instance._flag_jsxray_iocs(output, res)
        assert check_section_equality(res.sections[0], correct_res_sec)

    @staticmethod
    @pytest.mark.parametrize("data, length, res", [
        (b"blah", None, "blah"),
        (b"blah", 10, "blah"),
        (b"blahblahblahblah", 10, "blahblahbl..."),
    ])
    def test_truncate(data, length, res):
        from jsjaws import truncate
        if length:
            assert truncate(data, length) == res
        else:
            assert truncate(data) == res

    @staticmethod
    @pytest.mark.parametrize("data, expected_result", [
        (b"blah", '8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52')
    ])
    def test_get_id_from_data(data, expected_result):
        from os import remove
        from jsjaws import get_id_from_data
        some_file = "some_file.txt"
        with open(some_file, "wb") as f:
            f.write(b"blah")
        assert get_id_from_data(some_file) == expected_result
        remove(some_file)

    @staticmethod
    def test_extract_malware_jail_iocs(jsjaws_class_instance):
        from assemblyline_v4_service.common.result import Result, ResultSection
        correct_res_sec = ResultSection("MalwareJail extracted the following IOCs")
        correct_res_sec.set_heuristic(2)
        correct_res_sec.tags = {
            "network.dynamic.domain": ["blah.com"],
            "network.dynamic.uri": ["https://blah.com/blah.exe"],
            "network.dynamic.uri_path": ["/blah.exe"],
        }
        res = Result()
        output = ["https://blah.com/blah.exe"]
        jsjaws_class_instance._extract_malware_jail_iocs(output, res)
        assert check_section_equality(res.sections[0], correct_res_sec)
