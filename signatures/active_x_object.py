"""
These are all of the signatures related to using ActiveXObjects
"""

from signatures.abstracts import Signature


class ActiveXObject(Signature):
    # Supported by https://github.com/target/strelka/blob/3439953e6aa2dafb68ea73c3977da11f87aeacdf/src/python/strelka/scanners/scan_javascript.py#L35
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="active_x_object",
            description="JavaScript creates an ActiveXObject",
            indicators=["ActiveXObject"],
            severity=0,
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)


class GetObject(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="get_object",
            description="JavaScript returns a reference to an object provided by an ActiveX component",
            indicators=["GetObject"],
            severity=0,
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)


class XMLHTTP(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="xml_http",
            description="JavaScript creates an ActiveXObject to perform XML HTTP requests",
            indicators=["ActiveXObject", "Microsoft.XMLHTTP"],
            severity=0,
        )

    def process_output(self, output):
        self.check_indicators_in_list(output, match_all=True)
