"""
These are all of the signatures related to loading a file into memory
"""
from signatures.abstracts import Signature


class LoadsLocalFile(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="loads_local_file",
            description="JavaScript loads a local file from disk",
            indicators=[".LoadFromFile"],
            severity=0
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)