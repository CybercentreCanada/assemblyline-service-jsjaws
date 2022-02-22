"""
These are all of the signatures related to hiding malicious behaviour
"""
from signatures.abstracts import Signature


class HideObjects(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="hide_object",
            description="JavaScript removes objects that were recently appended",
            indicators=["document.body.appendChild(", "document.body.removeChild("],
            severity=0
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)
