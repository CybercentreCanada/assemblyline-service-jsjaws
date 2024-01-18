"""
These are all of the signatures related to saving a file
"""
from assemblyline.common.str_utils import safe_str
from signatures.abstracts import ANY, Signature

# List of commands used to save a file to disk
save_commands = ["saveToFile", "msSaveOrOpenBlob(", "saveAs(", "new File("]


class SaveToFile(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="save_to_file",
            description="JavaScript writes data to disk",
            indicators=save_commands,
            severity=0,
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
            severity=2,
        )

    def process_output(self, output):
        indicator_list = [
            {"method": ANY, "indicators": save_commands},
            {"method": ANY, "indicators": self.indicators},
        ]
        self.check_multiple_indicators_in_list(output, indicator_list)


class WritesArchive(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="writes_archive",
            description="JavaScript writes archive file to disk",
            indicators=["\\.zip", "\\.iso"],
            severity=3,
        )

    def process_output(self, output):
        extension_results = []
        results = []

        # First look for file extensions
        extension_regex = f"(?i)({'|'.join(self.indicators)})\\b"
        for line in output:
            split_line = line.split("] ")
            if len(split_line) == 2:
                string = split_line[1]
            if self.check_regex(extension_regex, string.lower()):
                extension_results.append(string)

        # Next look for the command
        escaped_save_commands = [save_command.replace("(", "\\(") for save_command in save_commands]
        commands_regex = f"({'|'.join(escaped_save_commands)})"
        for line in extension_results:
            if self.check_regex(commands_regex, line):
                results.append(line)

        results_set = sorted(set(results))
        for result in results_set:
            self.marks.append(safe_str(result).strip())


class CopyFile(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="copy_file",
            description="JavaScript uses the FileSystemObject to copy a file",
            indicators=[".CopyFile"],
            severity=0,
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
            severity=3,
        )

    def process_output(self, output):
        self.check_indicators_in_list(output, match_all=True)
