"""
These are all of the signatures related to saving a file
"""

import re

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
        for line in output:
            line = self.remove_timestamp(line)
            lower = line.lower()
            if re.search(r"[.](exe|dll)\b", lower) and any(
                save_command.lower() in lower for save_command in save_commands
            ):
                self.add_mark(line)


class WritesArchive(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="writes_archive",
            description="JavaScript writes archive file to disk",
            # File extensions based on https://github.com/CybercentreCanada/assemblyline-service-cape/blob/2412416fd8040897d25d00bdaba6356d514398f4/cape/cape_main.py#L1343
            indicators=["zip", "iso", "rar", "vhd", "udf", "7z"],
            severity=3,
        )

    def process_output(self, output):
        extension_results = []
        results = []

        # First look for file extensions
        extension_regex = f"(?i)\\w[.]({'|'.join(self.indicators)})\\b"
        for line in output:
            string = self.remove_timestamp(line)
            if re.search(extension_regex, string.lower()):
                extension_results.append(string)

        # Next look for the command
        escaped_save_commands = [save_command.replace("(", "\\(") for save_command in save_commands]
        commands_regex = f"({'|'.join(escaped_save_commands)})"
        for line in extension_results:
            if re.search(commands_regex, line):
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
