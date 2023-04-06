"""
These are all of the signatures related to writing data to the console
"""
from signatures.abstracts import Signature


class ConsoleOutput(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="console_output",
            description="JavaScript writes data to the console",
            indicators=["console.log"],
            severity=0
        )

    def process_output(self, output):
        self.check_indicators_in_list(output, match_all=True)
