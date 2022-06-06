"""
These are all of the signatures related to saving a file
"""
from signatures.abstracts import Signature


# List of commands used to save a file to disk
save_commands = ["SaveToFile", "navigator.msSaveOrOpenBlob(", "saveAs("]


class SaveToFile(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="save_to_file",
            description="JavaScript writes data to disk",
            indicators=save_commands,
            severity=0
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)


class WritesExecutable(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="writes_executable",
            description="JavaScript writes executable file to disk",
            indicators=[".exe"],
            severity=0
        )

    def process_output(self, output):
        indicator_list = [
            {
                "method": "any",
                "indicators": save_commands
            },
            {
                "method": "any",
                "indicators": self.indicators
            },
        ]
        self.check_multiple_indicators_in_list(output, indicator_list)


class WritesArchive(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="writes_archive",
            description="JavaScript writes archive file to disk",
            indicators=[".zip", ".iso"],
            severity=0
        )

    def process_output(self, output):
        indicator_list = [
            {
                "method": "any",
                "indicators": save_commands
            },
            {
                "method": "any",
                "indicators": self.indicators
            },
        ]
        self.check_multiple_indicators_in_list(output, indicator_list)
