import os
import pytest
import shutil
import requests_mock

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
        service_name='metadefender',
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
def metadefender_class_instance(mocker, dummy_api_interface):
    create_tmp_manifest()
    try:
        from metadefender import MetaDefender
        mocker.patch.object(MetaDefender, "get_api_interface", return_value=dummy_api_interface)
        yield MetaDefender()
    finally:
        remove_tmp_manifest()


@pytest.fixture
def dummy_api_interface():
    class DummyApiInterface(object):
        def __int__(self):
            pass

        @staticmethod
        def get_safelist(*args):
            return {}
    return DummyApiInterface


class TestAvHitSection:
    @classmethod
    def setup_class(cls):
        create_tmp_manifest()

    @classmethod
    def teardown_class(cls):
        remove_tmp_manifest()

    @staticmethod
    def test_init(mocker):
        from json import dumps
        from assemblyline_v4_service.common.result import BODY_FORMAT, ResultSection, Heuristic
        mocker.patch("assemblyline_v4_service.common.api.ServiceAPIError")
        from metadefender import AvHitSection
        av_name = "blah"
        virus_name = "blah"
        engine = {}
        heur_id = 1
        sig_score_rev_map = {}
        kw_score_rev_map = {}
        safelist_match = []
        actual_res_sec = AvHitSection(av_name, virus_name, engine, heur_id, sig_score_rev_map,
                                     kw_score_rev_map, safelist_match)
        correct_result_section = ResultSection(f"{av_name} identified the file as {virus_name}")
        correct_result_section.heuristic = Heuristic(1)
        correct_result_section.heuristic.add_signature_id(f"{av_name}.{virus_name}")
        correct_result_section.tags = {"av.virus_name": [virus_name]}
        correct_result_section.body = dumps({"av_name": av_name, "virus_name": virus_name, "scan_result": "infected", "engine_version": "unknown", "engine_definition_time": "unknown"})
        correct_result_section.body_format = BODY_FORMAT.KEY_VALUE
        assert check_section_equality(actual_res_sec, correct_result_section)

        engine = {"version": "blah", "def_time": 1}
        heur_id = 2
        safelist_match = ["blah"]
        actual_res_sec = AvHitSection(av_name, virus_name, engine, heur_id, sig_score_rev_map,
                                      kw_score_rev_map, safelist_match)
        correct_result_section.tags = {"av.virus_name": [virus_name]}
        correct_result_section.heuristic = Heuristic(2)
        correct_result_section.heuristic.add_signature_id(f"{av_name}.{virus_name}", 0)
        correct_result_section.body = dumps({"av_name": av_name, "virus_name": virus_name, "scan_result": "suspicious", "engine_version": "blah", "engine_definition_time": 1})
        assert check_section_equality(actual_res_sec, correct_result_section)

        kw_score_rev_map = {"bla": 1}
        actual_res_sec = AvHitSection(av_name, virus_name, engine, heur_id, sig_score_rev_map,
                                      kw_score_rev_map, safelist_match)
        correct_result_section.heuristic = Heuristic(2)
        correct_result_section.heuristic.add_signature_id(f"{av_name}.{virus_name}", 1)
        correct_result_section.body = dumps({"av_name": av_name, "virus_name": virus_name, "scan_result": "suspicious", "engine_version": "blah", "engine_definition_time": 1})
        assert check_section_equality(actual_res_sec, correct_result_section)

        kw_score_rev_map = {"bla": 1, "h": 2}
        actual_res_sec = AvHitSection(av_name, virus_name, engine, heur_id, sig_score_rev_map,
                                      kw_score_rev_map, safelist_match)
        correct_result_section.heuristic = Heuristic(2)
        correct_result_section.heuristic.add_signature_id(f"{av_name}.{virus_name}", 2)
        correct_result_section.body = dumps({"av_name": av_name, "virus_name": virus_name, "scan_result": "suspicious", "engine_version": "blah", "engine_definition_time": 1})
        assert check_section_equality(actual_res_sec, correct_result_section)

        sig_score_rev_map = {f"{av_name}.{virus_name}": 10}
        actual_res_sec = AvHitSection(av_name, virus_name, engine, heur_id, sig_score_rev_map,
                                      kw_score_rev_map, safelist_match)
        correct_result_section.heuristic = Heuristic(2)
        correct_result_section.heuristic.add_signature_id(f"{av_name}.{virus_name}", 10)
        correct_result_section.body = dumps({"av_name": av_name, "virus_name": virus_name, "scan_result": "suspicious", "engine_version": "blah", "engine_definition_time": 1})
        assert check_section_equality(actual_res_sec, correct_result_section)


class TestAvErrorSection:
    @classmethod
    def setup_class(cls):
        create_tmp_manifest()

    @classmethod
    def teardown_class(cls):
        remove_tmp_manifest()

    @staticmethod
    def test_init(mocker):
        from assemblyline_v4_service.common.result import ResultSection
        mocker.patch("assemblyline_v4_service.common.api.ServiceAPIError")
        from metadefender import AvErrorSection
        av_name = "blah"
        engine = {}
        actual_res_sec = AvErrorSection(av_name, engine)
        correct_result_section = ResultSection(f"{av_name} failed to scan the file")
        correct_result_section.body = ""
        assert check_section_equality(actual_res_sec, correct_result_section)

        engine = {"version": "blah", "def_time": "blah"}
        actual_res_sec = AvErrorSection(av_name, engine)
        correct_result_section = ResultSection(f"{av_name} failed to scan the file")
        correct_result_section.body = f"Engine: {engine['version']} :: Definition: {engine['def_time']}"
        assert check_section_equality(actual_res_sec, correct_result_section)


class TestMetaDefender:
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
    def test_init(metadefender_class_instance):
        assert metadefender_class_instance.session is None
        assert metadefender_class_instance.timeout == 40
        assert metadefender_class_instance.nodes == {}
        assert metadefender_class_instance.current_node == None
        assert metadefender_class_instance.start_time == None
        assert metadefender_class_instance.headers == None
        assert metadefender_class_instance.blocklist == None
        assert metadefender_class_instance.kw_score_revision_map == None
        assert metadefender_class_instance.sig_score_revision_map == None
        assert metadefender_class_instance.safelist_match == []

    @staticmethod
    def test_start(metadefender_class_instance, mocker):
        from requests import Session
        original_value = metadefender_class_instance.config["base_url"]
        mocker.patch.object(metadefender_class_instance, "_get_version_map")
        # base_url as str
        with pytest.raises(Exception):  # node engine count of 0
            metadefender_class_instance.start()
        # base_url as list
        metadefender_class_instance.config["base_url"] = [original_value]
        with pytest.raises(Exception):  # node engine count of 0
            metadefender_class_instance.start()
        # base_url as number
        metadefender_class_instance.config["base_url"] = 1
        with pytest.raises(Exception):  # node engine count of 0
            metadefender_class_instance.start()

        mocker.patch.object(metadefender_class_instance, "_get_version_map", side_effect=Exception)
        metadefender_class_instance.config["base_url"] = original_value
        with pytest.raises(Exception):  # all nodes are down
            metadefender_class_instance.start()

        # Successful _get_version_map
        mocker.patch.object(metadefender_class_instance, "_get_version_map")
        sample_url = "http://1.1.1.1:8008/"
        metadefender_class_instance.nodes[sample_url] = {"engine_count": 1}
        metadefender_class_instance.start()
        assert metadefender_class_instance.blocklist == metadefender_class_instance.config["av_config"]["blocklist"]
        assert metadefender_class_instance.kw_score_revision_map == metadefender_class_instance.config["av_config"]["kw_score_revision_map"]
        assert metadefender_class_instance.sig_score_revision_map == metadefender_class_instance.config["av_config"]["sig_score_revision_map"]
        assert isinstance(metadefender_class_instance.session, Session)
        assert metadefender_class_instance.current_node == sample_url
        assert type(metadefender_class_instance.start_time) is float
        assert metadefender_class_instance.nodes[sample_url] == {"engine_count": 1}
        assert metadefender_class_instance.nodes[original_value].pop("oldest_dat")
        assert metadefender_class_instance.nodes[original_value] == {'average_queue_time': 0, 'engine_count': 0, 'engine_list': 'default', 'engine_map': {}, 'file_count': 0, 'newest_dat': '1970-01-01 00:00:00', 'queue_times': []}

    @staticmethod
    @pytest.mark.parametrize("name, correct_name",
                             [
                                 ("blah", "blah"),
                                 ("BLAH", "blah"),
                                 ("bla h", "blah"),
                                 ("bla!h", "blah"),
                                 ("blahav", "blah"),
                             ])
    def test_format_engine_name(name, correct_name, metadefender_class_instance):
        assert metadefender_class_instance._format_engine_name(name) == correct_name

    @staticmethod
    def test_get_version_map(metadefender_class_instance):
        from requests import Session, exceptions
        from assemblyline.common.isotime import epoch_to_local
        metadefender_class_instance.session = Session()
        node = "http://blah:1/"
        metadefender_class_instance.nodes[node] = {}
        with requests_mock.Mocker() as m:
            m.get(f"{node}stat/engines", status_code=200, json=[])
            metadefender_class_instance._get_version_map(node)
            metadefender_class_instance.nodes[node].pop("oldest_dat")
            assert metadefender_class_instance.nodes[node] == {"engine_count": 0, "newest_dat": epoch_to_local(0)[:19], "engine_list": ""}

            with pytest.raises(Exception):
                m.get(f"{node}stat/engines", exc=exceptions.Timeout)
                metadefender_class_instance._get_version_map(node)

            with pytest.raises(Exception):
                m.get(f"{node}stat/engines", exc=exceptions.ConnectionError)
                metadefender_class_instance._get_version_map(node)

            # MD Version 4
            metadefender_class_instance.nodes[node] = {"engine_map": {}}
            m.get(f"{node}stat/engines", status_code=200, json=[{"active": False, "eng_name": "blah", "eng_ver": "blah", "def_time": "1999-09-09T12:12:12", "engine_type": "blah"}])
            metadefender_class_instance._get_version_map(node)
            metadefender_class_instance.nodes[node].pop("oldest_dat")
            assert metadefender_class_instance.nodes[node] == {"engine_count": 0, "newest_dat": '1999-09-09 12:12:14', "engine_list": 'blahblah1999-09-09T12:12:12', "engine_map": {'blah': {'def_time': '1999-09-09 12:12:14', 'version': 'blah'}}}

            m.get(f"{node}stat/engines", status_code=200, json=[{"active": True, "state": "blah", "eng_name": "blah", "eng_ver": "blah", "def_time": "1999-09-09T12:12:12", "engine_type": "blah"}])
            metadefender_class_instance._get_version_map(node)
            metadefender_class_instance.nodes[node].pop("oldest_dat")
            assert metadefender_class_instance.nodes[node] == {"engine_count": 1, "newest_dat": '1999-09-09 12:12:14', "engine_list": 'blahblah1999-09-09T12:12:12', "engine_map": {'blah': {'def_time': '1999-09-09 12:12:14', 'version': 'blah'}}}

            # MD Version 3
            metadefender_class_instance.config["md_version"] = 3
            m.get(f"{node}stat/engines", status_code=200, json=[{"active": False, "eng_name": "blah", "eng_ver": "blah", "def_time": "09-09-1999T12:12:12", "engine_type": "blah", "eng_type": "blah"}])
            metadefender_class_instance._get_version_map(node)
            metadefender_class_instance.nodes[node].pop("oldest_dat")
            assert metadefender_class_instance.nodes[node] == {"engine_count": 0, "newest_dat": '1999-09-09 12:12:12', "engine_list": 'blahblah1999-09-09T12:12:12Z', "engine_map": {'blah': {'def_time': '1999-09-09 12:12:12', 'version': 'blah'}}}

            # etype
            for etype in ["av", "Bundled engine"]:
                m.get(f"{node}stat/engines", status_code=200, json=[{"active": False, "eng_name": "blah", "eng_ver": "blah", "def_time": "09-09-1999T12:12:12", "engine_type": "blah", "eng_type": etype}])
                metadefender_class_instance._get_version_map(node)
                assert metadefender_class_instance.nodes[node] == {"engine_count": 0, "newest_dat": '1999-09-09 12:12:12', "engine_list": 'blahblah1999-09-09T12:12:12Z', "engine_map": {'blah': {'def_time': '1999-09-09 12:12:12', 'version': 'blah'}}, "oldest_dat": '1999-09-09 12:12:12',}

            # Invalid MD Version
            metadefender_class_instance.config["md_version"] = 2
            with pytest.raises(Exception):
                m.get(f"{node}stat/engines", status_code=200, json=[{"active": False, "eng_name": "blah", "eng_ver": "blah", "def_time": "09-09-1999T12:12:12", "engine_type": "blah", "eng_type": "blah"}])
                metadefender_class_instance._get_version_map(node)

            # Failed states
            metadefender_class_instance.config["md_version"] = 4
            for state in ["removed", "temporary failed", "permanently failed"]:
                m.get(f"{node}stat/engines", status_code=200, json=[{"active": False, "state": state, "eng_name": "blah", "eng_ver": "blah", "def_time": "1999-09-09T12:12:12", "engine_type": "blah"}])
                metadefender_class_instance._get_version_map(node)
                metadefender_class_instance.nodes[node].pop("oldest_dat")
                assert metadefender_class_instance.nodes[node] == {"engine_count": 0, "newest_dat": '1999-09-09 12:12:14', "engine_list": 'blahblah1999-09-09T12:12:12', "engine_map": {'blah': {'def_time': '1999-09-09 12:12:14', 'version': 'blah'}}}

    @staticmethod
    def test_get_tool_version(metadefender_class_instance):
        metadefender_class_instance.nodes["blah"] = {"engine_list": "blah"}
        assert metadefender_class_instance.get_tool_version() == "6f1ed002ab5595859014ebf0951522d9"

    @staticmethod
    @pytest.mark.parametrize("sample", samples)
    def test_execute(sample, metadefender_class_instance, mocker):
        from assemblyline_v4_service.common.task import Task
        from assemblyline_v4_service.common.result import Result
        from assemblyline.odm.messages.task import Task as ServiceTask
        from assemblyline_v4_service.common.request import ServiceRequest
        import json
        metadefender_class_instance.nodes["blah"] = {"engine_count": 1, "oldest_dat": 1, "newest_dat": 1}
        mocker.patch.object(metadefender_class_instance, "_get_version_map")
        metadefender_class_instance.start()

        service_task = ServiceTask(sample)
        task = Task(service_task)
        metadefender_class_instance._task = task
        service_request = ServiceRequest(task)

        mocker.patch.object(metadefender_class_instance, "scan_file")
        mocker.patch.object(metadefender_class_instance, "new_node")
        mocker.patch.object(metadefender_class_instance, "parse_results", return_value=Result())

        # Actually executing the sample
        metadefender_class_instance.execute(service_request)

        # Get the result of execute() from the test method
        test_result = task.get_service_result()

        # Get the assumed "correct" result of the sample
        correct_result_path = os.path.join(TEST_DIR, "results", task.file_name + ".json")
        with open(correct_result_path, "r") as f:
            correct_result = json.loads(f.read())
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

        # For coverage
        metadefender_class_instance.config["max_node_time"] = 0
        metadefender_class_instance.execute(service_request)

        metadefender_class_instance.config["max_node_time"] = 1000
        metadefender_class_instance.config["min_node_time"] = 0
        metadefender_class_instance.execute(service_request)

    @staticmethod
    def test_get_scan_results_by_data_id(metadefender_class_instance, mocker):
        from requests import Session, Response, Request, exceptions
        from assemblyline.common.exceptions import RecoverableError
        data_id = "blah"
        metadefender_class_instance.current_node = "http://blah/"
        metadefender_class_instance.session = Session()
        mocker.patch.object(metadefender_class_instance, "new_node")
        with requests_mock.Mocker() as m:
            m.get(f"{metadefender_class_instance.current_node}file/{data_id}", status_code=200)
            correct_response = Response()
            correct_response.status_code = 200
            correct_response.request = Request()
            correct_response.request.hostname = "blah"
            correct_response.request.netloc = "blah"
            correct_response.request.path = "/file/blah"
            correct_response.request.port = 80
            correct_response.request.query = ""
            correct_response.request.scheme = "http"
            correct_response.request.timeout = 40
            correct_response.url = "http://blah/file/blah"

            test_response = metadefender_class_instance.get_scan_results_by_data_id(data_id)
            assert test_response.status_code == correct_response.status_code
            assert test_response.request.hostname == correct_response.request.hostname
            assert test_response.request.netloc == correct_response.request.netloc
            assert test_response.request.path == correct_response.request.path
            assert test_response.request.port == correct_response.request.port
            assert test_response.request.query == correct_response.request.query
            assert test_response.request.scheme == correct_response.request.scheme
            assert test_response.request.timeout == correct_response.request.timeout
            assert test_response.url == correct_response.url

        with requests_mock.Mocker() as m:
            m.get(f"{metadefender_class_instance.current_node}file/{data_id}", exc=exceptions.Timeout)
            with pytest.raises(Exception):
                metadefender_class_instance.get_scan_results_by_data_id(data_id)

        with requests_mock.Mocker() as m:
            m.get(f"{metadefender_class_instance.current_node}file/{data_id}", exc=exceptions.ConnectionError)
            with pytest.raises(RecoverableError):
                mocker.patch.object(metadefender_class_instance, "new_node")
                metadefender_class_instance.get_scan_results_by_data_id(data_id)

    @staticmethod
    def test_new_node(metadefender_class_instance):
        from requests import Session
        metadefender_class_instance.nodes = {
            "blah1": {},
        }
        metadefender_class_instance.current_node = "blah1"
        metadefender_class_instance.new_node(force=False)
        assert metadefender_class_instance.current_node == "blah1"

        metadefender_class_instance.session = Session()
        metadefender_class_instance.nodes = {
            "blah1": {"file_count": 1},
            "blah2": {}
        }
        metadefender_class_instance.current_node = "blah1"
        metadefender_class_instance.new_node(force=False)
        assert metadefender_class_instance.current_node == "blah1"

        metadefender_class_instance.nodes = {
            "blah1": {"file_count": 2, "queue_times": [1, 2, 3, 4, 5]},
            "blah2": {"average_queue_time": 1}
        }
        metadefender_class_instance.current_node = "blah1"
        metadefender_class_instance.new_node(force=False)
        assert metadefender_class_instance.current_node == "blah2"

        metadefender_class_instance.nodes = {
            "blah1": {"file_count": 2, "queue_times": [1, 2, 3, 4, 5]},
            "blah2": {}
        }
        metadefender_class_instance.current_node = "blah1"
        metadefender_class_instance.new_node(force=True)
        assert metadefender_class_instance.current_node == "blah2"

        metadefender_class_instance.nodes = {
            "blah1": {"file_count": 2, "queue_times": [1, 2, 3, 4, 5]},
            "blah2": {"average_queue_time": 1}
        }
        metadefender_class_instance.current_node = "blah1"
        metadefender_class_instance.new_node(force=False, reset_queue=True)
        assert metadefender_class_instance.current_node == "blah2"
        assert metadefender_class_instance.nodes["blah1"]["average_queue_time"] == 0

    @staticmethod
    def test_scan_file(metadefender_class_instance, mocker):
        from requests import Session, Response, exceptions
        from assemblyline.common.exceptions import RecoverableError
        file_name = "blah.txt"
        with open(file_name, "w") as f:
            f.write("blah")
        metadefender_class_instance.current_node = "http://blah"
        metadefender_class_instance.nodes[metadefender_class_instance.current_node] = {}
        metadefender_class_instance.session = Session()
        mocker.patch.object(metadefender_class_instance, "new_node")
        with requests_mock.Mocker() as m:
            m.post(f"{metadefender_class_instance.current_node}/file", status_code=404)
            with pytest.raises(Exception):
                metadefender_class_instance.scan_file(file_name)

            m.post(f"{metadefender_class_instance.current_node}/file", exc=exceptions.Timeout)
            with pytest.raises(Exception):
                metadefender_class_instance.scan_file(file_name)

            m.post(f"{metadefender_class_instance.current_node}/file", exc=exceptions.ConnectionError)
            with pytest.raises(RecoverableError):
                metadefender_class_instance.scan_file(file_name)

            unsuccess_resp = Response()
            unsuccess_resp.status_code = 404
            unsuccess_resp._content = b"{}"
            mocker.patch.object(metadefender_class_instance, "get_scan_results_by_data_id", return_value=unsuccess_resp)
            m.post(f"{metadefender_class_instance.current_node}/file", status_code=200, json={"data_id": "blah"})
            assert metadefender_class_instance.scan_file(file_name) == {}

            success_resp = Response()
            success_resp.status_code = 200
            success_resp._content = b'{"scan_results": {"progress_percentage": 100}}'
            mocker.patch.object(metadefender_class_instance, "get_scan_results_by_data_id", return_value=success_resp)
            assert metadefender_class_instance.scan_file(file_name) == {'scan_results': {'progress_percentage': 100}}
            assert metadefender_class_instance.nodes[metadefender_class_instance.current_node] == {"timeout_count": 0, "timeout": 0}

            success_resp._content = b'{"scan_results": {}}'
            mocker.patch.object(metadefender_class_instance, "get_scan_results_by_data_id", return_value=success_resp)
            with pytest.raises(RecoverableError):
                metadefender_class_instance.scan_file(file_name)

    @staticmethod
    @pytest.mark.parametrize("response, correct_res_secs",
                             [
                                 ({}, []),
                                 ({"scan_results": {"progress_percentage": 100, "z": {"scan_result_i": 1, "threat_found": "blah", "scan_time": "blah"}}, "file_info": {"file_size": "blah"}, "process_info": {"queue_time": "blah", "processing_time": "blah"}}, [{"title_text": 'AV Detections as Infected or Suspicious', "subsections": [{"title_text": 'z identified the file as blah', "body": '{"av_name": "z", "virus_name": "blah", "scan_result": "infected", "engine_version": "blah", "engine_definition_time": "blah"}', "tags": {'av.virus_name': ['blah']}, "heuristic": {"heur_id": 1, "signatures": {'z.blah': 1}}}]}, {"title_text": 'CDR Successfully Executed', "body_format": "JSON", "body": "{}"}]),
                                 ({"scan_results": {"progress_percentage": 100, "a": {"scan_result_i": 1, "threat_found": "blah", "scan_time": "blah"}}, "file_info": {"file_size": "blah"}, "process_info": {"queue_time": "blah", "processing_time": "blah"}}, [{"title_text": 'AV Detections as Infected or Suspicious', "subsections": [{"title_text": 'z identified the file as blah', "body": '{"av_name": "z", "virus_name": "blah", "scan_result": "infected", "engine_version": "blah", "engine_definition_time": "blah"}', "tags": {'av.virus_name': ['blah']}, "heuristic": {"heur_id": 1, "signatures": {'z.blah': 1}}}]}, {"title_text": 'CDR Successfully Executed', "body_format": "JSON", "body": "{}"}]),
                                 ({"scan_results": {"progress_percentage": 100, "a": {"scan_result_i": 1, "threat_found": "blah", "scan_time": "blah"}}, "file_info": {"file_size": "blah"}, "process_info": {"queue_time": "blah", "processing_time": "blah"}}, [{"title_text": 'AV Detections as Infected or Suspicious', "subsections": [{"title_text": 'z identified the file as blah', "body": '{"av_name": "z", "virus_name": "blah", "scan_result": "infected", "engine_version": "blah", "engine_definition_time": "blah"}', "tags": {'av.virus_name': ['blah']}, "heuristic": {"heur_id": 1, "signatures": {'z.blah': 1}}}]}, {"title_text": 'CDR Successfully Executed', "body_format": "JSON", "body": "{}"}]),
                                 ({"scan_results": {"progress_percentage": 100, "z": {"scan_result_i": 2, "threat_found": "blah", "scan_time": "blah"}}, "file_info": {"file_size": "blah"}, "process_info": {"queue_time": "blah", "processing_time": "blah"}}, [{"title_text": 'AV Detections as Infected or Suspicious', "subsections": [{"title_text": 'z identified the file as blah', "body": '{"av_name": "z", "virus_name": "blah", "scan_result": "suspicious", "engine_version": "blah", "engine_definition_time": "blah"}', "tags": {'av.virus_name': ['blah']}, "heuristic": {"heur_id": 2, "signatures": {'z.blah': 1}}}]}, {"title_text": 'CDR Successfully Executed', "body_format": "JSON", "body": "{}"}]),
                                 ({"scan_results": {"progress_percentage": 100, "z": {"scan_result_i": 10, "scan_time": "blah"}}, "file_info": {"file_size": "blah"}, "process_info": {"queue_time": "blah", "processing_time": "blah"}}, [{"title_text": 'CDR Failed or No Malicious Files Found'}]),
                                 ({"scan_results": {"progress_percentage": 100, "b": {"scan_result_i": 10, "scan_time": "blah"}}, "file_info": {"file_size": "blah"}, "process_info": {"queue_time": "blah", "processing_time": "blah"}}, [{"title_text": 'CDR Failed or No Malicious Files Found'}]),
                                 ({"scan_results": {"progress_percentage": 100, "z": {"scan_result_i": 3, "scan_time": "blah"}}, "file_info": {"file_size": "blah"}, "process_info": {"queue_time": "blah", "processing_time": "blah"}}, [{"title_text": 'CDR Failed or No Malicious Files Found'}]),
                                 ({"scan_results": {"progress_percentage": 100, "z": {"scan_result_i": 0, "scan_time": "blah"}}, "file_info": {"file_size": "blah"}, "process_info": {"queue_time": "blah", "processing_time": "blah"}}, [{"title_text": 'CDR Failed or No Malicious Files Found'}]),
                                 ({"scan_results": {"progress_percentage": 100, "z": {"scan_result_i": 0, "scan_time": "blah"}}, "file_info": {"file_size": "blah"}, "process_info": {"queue_time": "blah", "processing_time": "blah", "progress_percentage": 100, "post_processing": {"actions_failed": ["blah"], "actions_ran": []}}}, [{"title_text": 'CDR Failed or No Malicious Files Found'}]),
                                 ({"scan_results": {"progress_percentage": 100, "z": {"scan_result_i": 0, "scan_time": "blah"}}, "file_info": {"file_size": "blah"}, "process_info": {"queue_time": "blah", "processing_time": "blah", "progress_percentage": 100, "post_processing": {"actions_failed": [], "actions_ran": ["blah"]}}}, [{"title_text": 'CDR Successfully Executed', "body_format": "JSON", "body": '{"actions_failed": [], "actions_ran": ["blah"]}'}]),
                                 ({"scan_results": {"progress_percentage": 100, "z": {"scan_result_i": 0, "scan_time": "blah"}, "y": {"scan_result_i": 1, "scan_time": "blah", "threat_found": "blah"}}, "file_info": {"file_size": "blah"}, "process_info": {"queue_time": "blah", "processing_time": "blah", "progress_percentage": 100, "post_processing": {"actions_failed": [], "actions_ran": ["blah"]}}}, [{"title_text": 'AV Detections as Infected or Suspicious', "subsections": [{"title_text": 'y identified the file as blah', "tags": {'av.virus_name': ['blah']}, "body": '{"av_name": "y", "virus_name": "blah", "scan_result": "infected", "engine_version": "blah", "engine_definition_time": "blah"}', "body_format": "KEY_VALUE", "heuristic": {"heur_id": 1, "signatures": {'y.blah': 1}}}]}, {"title_text": 'Failed to Scan or No Threats Detected', "subsections": [{"title_text": 'No Threat Detected by AV Engine(s)', "body_format": "KEY_VALUE", "body": '{"no_threat_detected": ["z"]}'}]}, {"title_text": 'CDR Successfully Executed', "body": '{"actions_failed": [], "actions_ran": ["blah"]}', "body_format": "JSON"}]),
                             ])
    def test_parse_results(response, correct_res_secs, metadefender_class_instance):
        from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT, Heuristic
        metadefender_class_instance.blocklist = ["a"]
        metadefender_class_instance.sig_score_revision_map = {}
        metadefender_class_instance.kw_score_revision_map = {}
        metadefender_class_instance.current_node = "http://blah"
        metadefender_class_instance.nodes[metadefender_class_instance.current_node] = {"engine_map": {"z": {"version": "blah", "def_time": "blah"}, "y": {"version": "blah", "def_time": "blah"}}, "queue_times": [], "file_count": 0}
        correct_result = Result()
        for correct_res_sec in correct_res_secs:
            section = ResultSection(
                correct_res_sec["title_text"],
                body_format=BODY_FORMAT.TEXT if not correct_res_sec.get("body_format") else BODY_FORMAT.JSON,
                body=correct_res_sec.get("body"))
            for subsec in correct_res_sec.get("subsections", []):
                subsection = ResultSection(
                    subsec["title_text"],
                    body=subsec["body"],
                    body_format=BODY_FORMAT.KEY_VALUE,
                    tags=subsec.get("tags"),
                )
                if subsec.get("heuristic"):
                    heur = Heuristic(subsec["heuristic"]["heur_id"])
                    heur.signatures = subsec["heuristic"]["signatures"]
                    subsection.heuristic = heur
                section.add_subsection(subsection)
            correct_result.add_section(section)
        actual_result = metadefender_class_instance.parse_results(response)
        for index, section in enumerate(actual_result.sections):
            assert check_section_equality(section, correct_result.sections[index])


