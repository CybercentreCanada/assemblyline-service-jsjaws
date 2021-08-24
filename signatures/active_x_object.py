"""
These are all of the signatures related to using ActiveXObjects
"""
from signatures.abstracts import Signature


class ActiveXObject(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="active_x_object",
            description="JavaScript creates an ActiveXObject",
            indicators=["ActiveXObject"],
            severity=1
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
            severity=2
        )

    def process_output(self, output):
        self.check_indicators_in_list(output, match_all=True)


class FileSystemObject(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="file_system_object",
            description="JavaScript creates an ActiveXObject to gain access to the computer's file system",
            indicators=["ActiveXObject", "Scripting.FileSystemObject"],
            severity=2
        )

    def process_output(self, output):
        self.check_indicators_in_list(output, match_all=True)