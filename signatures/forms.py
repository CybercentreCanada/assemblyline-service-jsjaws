"""
These are all of the signatures related to forms
"""
from signatures.abstracts import Signature


class FormActionURI(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="form_action_uri",
            description="A form is created and the action submits to a URI.",
            indicators=["HTMLFormElement ", ".action was set to a URI"],
            severity=0,
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)
