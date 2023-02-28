"""
These are all of the signatures related to saving a file
"""
from signatures.abstracts import Signature


# List of commands used to save a file to disk
save_commands = ["saveToFile", "msSaveOrOpenBlob(", "saveAs(", "new File("]


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
            indicators=[".exe", ".dll"],
            severity=2
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
            severity=3
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


class CopyFile(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="copy_file",
            description="JavaScript uses the FileSystemObject to copy a file",
            indicators=[".CopyFile"],
            severity=0
        )

    def process_output(self, output):
        self.check_indicators_in_list(output, match_all=True)


class OverwriteRunDll(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="overwrite_rundll",
            description="JavaScript uses the FileSystemObject to overwrite rundll32.exe",
            indicators=[".CopyFile", "rundll32.exe"],
            severity=3
        )

    def process_output(self, output):
        self.check_indicators_in_list(output, match_all=True)
