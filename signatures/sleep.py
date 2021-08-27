"""
These are all of the signatures related to causing execution to delay
"""
from signatures.abstracts import Signature


class Sleep(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="sleep",
            description="JavaScript attempts to sleep",
            indicators=["WScript.Sleep", ".setTimeout("],
            severity=1
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)


class AntiSandboxTimeout(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="antisandbox_timeout",
            description="JavaScript file managed to delay execution until the sandbox timed out",
            indicators=["Script execution timed out after"],
            severity=2
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)
