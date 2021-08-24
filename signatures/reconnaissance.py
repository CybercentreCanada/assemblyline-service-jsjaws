"""
These are all of the signatures related to gathering information about the environment
"""
from signatures.abstracts import Signature


class ExpandEnvStrings(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="env_str_recon",
            description="JavaScript looks at the environment strings",
            indicators=[".ExpandEnvironmentStrings"],
            severity=1
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)


class DriveObject(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="drive_object",
            description="JavaScript creates an object representing a hard drive",
            indicators=["DriveObject"],
            severity=1
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)


class FileSystemObject(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="file_system_object",
            description="JavaScript creates an ActiveXObject to gain access to the computer's file system",
            indicators=["Scripting.FileSystemObject"],
            severity=2
        )

    def process_output(self, output):
        self.check_indicators_in_list(output, match_all=True)