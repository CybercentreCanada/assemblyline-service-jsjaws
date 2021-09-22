"""
These are all of the signatures related to saving a file
"""
from signatures.abstracts import Signature


class SaveToFile(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="save_to_file",
            description="JavaScript writes data to disk",
            indicators=["SaveToFile"],
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
            indicators=["SaveToFile", ".exe"],
            severity=0
        )

    def process_output(self, output):
        self.check_indicators_in_list(output, match_all=True)
