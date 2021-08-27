"""
These are all of the signatures related to invalid JavaScript
"""
from signatures.abstracts import Signature


class InvalidJS(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="invalid_js",
            description="JavaScript is invalid",
            indicators=["SyntaxError: Invalid or unexpected token"],
            severity=0
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)
