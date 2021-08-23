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

    @staticmethod
    def test_start(jsjaws_class_instance):
        from os.path import exists
        from jsjaws import SERVICE_DIR, PAYLOAD_EXTRACTION_DIR, SANDBOX_ENV_DIR
        jsjaws_class_instance.start()
        assert jsjaws_class_instance.artifact_list == []
        assert exists(SERVICE_DIR)
        assert exists(PAYLOAD_EXTRACTION_DIR)
        assert exists(SANDBOX_ENV_DIR)

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

        mocker.patch.object(jsjaws_class_instance, "_cleanup_previous_exec")
        mocker.patch.object(jsjaws_class_instance, "_run_signatures")
        mocker.patch.object(jsjaws_class_instance, "_extract_wscript")
        mocker.patch.object(jsjaws_class_instance, "_extract_payloads")
        mocker.patch.object(jsjaws_class_instance, "_extract_urls")
        mocker.patch.object(jsjaws_class_instance, "_extract_supplementary")
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
        }
        jsjaws_class_instance._task = task
        service_request = ServiceRequest(task)

        # Actually executing the sample
        jsjaws_class_instance.execute(service_request)

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
        service_request.task.service_config["wscipt_only"] = True
        jsjaws_class_instance.execute(service_request)

    @staticmethod
    def test_cleanup_previous_exec(jsjaws_class_instance):
        from os.path import exists
        from jsjaws import PAYLOAD_EXTRACTION_DIR, SANDBOX_ENV_DUMP_PATH, EXTRACTED_WSCRIPT_PATH
        # Setting the stage
        payload_path = f"{PAYLOAD_EXTRACTION_DIR}/blah.txt"
        with open(payload_path, "w") as f:
            f.write("blah")
        with open(SANDBOX_ENV_DUMP_PATH, "w") as f:
            f.write("blah")
        with open(EXTRACTED_WSCRIPT_PATH, "w") as f:
            f.write("blah")
        jsjaws_class_instance._cleanup_previous_exec()
        assert not exists(payload_path)
        assert not exists(SANDBOX_ENV_DUMP_PATH)
        assert not exists(EXTRACTED_WSCRIPT_PATH)

    @staticmethod
    def test_extract_wscript(jsjaws_class_instance, mocker):
        from jsjaws import EXTRACTED_WSCRIPT_PATH, EXTRACTED_WSCRIPT
        from os.path import exists
        from assemblyline_v4_service.common.result import Result
        mocker.patch.object(jsjaws_class_instance, "_extract_iocs_from_text_blob")
        output = ["WScript.Shell[4].Run(super evil script, 0, undefined)"]
        res = Result()
        jsjaws_class_instance.artifact_list = []
        jsjaws_class_instance._extract_wscript(output, res)
        assert exists(EXTRACTED_WSCRIPT_PATH)
        assert jsjaws_class_instance.artifact_list[0] == {
            "name": EXTRACTED_WSCRIPT,
            "path": EXTRACTED_WSCRIPT_PATH,
            "description": "Extracted WScript",
            "to_be_extracted": True
        }

    @staticmethod
    def test_extract_payloads(jsjaws_class_instance):
        from jsjaws import PAYLOAD_EXTRACTION_DIR, URLS_JSON_PATH, EXTRACTED_WSCRIPT_PATH
        jsjaws_class_instance.config["max_payloads_extracted"] = 2

        # Zero bytes file
        with open(f"{PAYLOAD_EXTRACTION_DIR}/blah1.txt", "a+") as f:
            pass

        # URLS_JSON_PATH file
        with open(URLS_JSON_PATH, "a+") as f:
            f.write("blah")

        # EXTRACTED_WSCRIPT_PATH file
        with open(EXTRACTED_WSCRIPT_PATH, "a+") as f:
            f.write("blah")

        # valid file 1
        valid_file_name1 = "blah2.txt"
        valid_file_path1 = f"{PAYLOAD_EXTRACTION_DIR}{valid_file_name1}"
        with open(valid_file_path1, "w") as f:
            f.write("blah")

        # valid file 2
        valid_file_name2 = "blah3.txt"
        valid_file_path2 = f"{PAYLOAD_EXTRACTION_DIR}{valid_file_name2}"
        with open(valid_file_path2, "w") as f:
            f.write("blah")

        jsjaws_class_instance.artifact_list = []
        jsjaws_class_instance._extract_payloads("blah", False)
        assert jsjaws_class_instance.artifact_list[0] == {
            "name": valid_file_name1,
            "path": valid_file_path1,
            "description": "Extracted Payload",
            "to_be_extracted": True
        }
        jsjaws_class_instance._cleanup_previous_exec()

    @staticmethod
    def test_extract_urls(jsjaws_class_instance):
        from jsjaws import URLS_JSON_PATH
        from json import dumps
        from assemblyline_v4_service.common.result import ResultSection, BODY_FORMAT
        body = [
                {"url": "http://blah.ca/blah.exe"},
                {"url": "http://1.1.1.1/blah.exe"},
                {"url": "blahblahblah"},
            ]
        with open(URLS_JSON_PATH, "w") as f:
            f.write(dumps(body))
        from assemblyline_v4_service.common.result import Result
        result = Result()
        jsjaws_class_instance._extract_urls(result)
        correct_res_sec = ResultSection("URLs", body_format=BODY_FORMAT.TABLE, body=dumps(body),
                                        tags={
                                            "network.dynamic.uri": ["http://blah.ca/blah.exe", "http://1.1.1.1/blah.exe"],
                                            "network.dynamic.domain": ["blah.ca", "blah.exe"],
                                            "network.dynamic.ip": ["1.1.1.1"],
                                            "network.dynamic.uri_path": ["/blah.exe"],
                                            "file.string.extracted": ["blahblahblah"]
                                        })
        correct_res_sec.set_heuristic(1)
        assert check_section_equality(result.sections[0], correct_res_sec)

    @staticmethod
    def test_extract_supplementary(jsjaws_class_instance):
        from jsjaws import SANDBOX_ENV_DUMP, SANDBOX_ENV_DUMP_PATH, MALWARE_JAIL_OUTPUT, MALWARE_JAIL_OUTPUT_PATH
        jsjaws_class_instance.artifact_list = []
        output = ["blah"]
        jsjaws_class_instance._extract_supplementary(output)
        assert jsjaws_class_instance.artifact_list[0] == {
            "name": SANDBOX_ENV_DUMP,
            "path": SANDBOX_ENV_DUMP_PATH,
            "description": "Sandbox Environment Details",
            "to_be_extracted": False
        }
        assert jsjaws_class_instance.artifact_list[1] == {
            "name": MALWARE_JAIL_OUTPUT,
            "path": MALWARE_JAIL_OUTPUT_PATH,
            "description": "Malware Jail Output",
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
        correct_subsection.add_line("\t\tSaveToFile")
        jsjaws_class_instance._run_signatures(output, result)
        assert check_section_equality(result.sections[0], correct_section)

    @staticmethod
    def test_process_signature():
        # NOTE that this method is tested in test_run_signatures
        assert True

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
