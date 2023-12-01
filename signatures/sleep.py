"""
These are all of the signatures related to causing execution to delay
"""
from signatures.abstracts import Signature


class Sleep(Signature):
    # Supported by https://github.com/CYB3RMX/Qu1cksc0pe/blob/ad3105ab9d3363df013ff95bae218f5c374a93fb/Systems/Multiple/malicious_html_codes.json#L37
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="sleep",
            description="JavaScript attempts to sleep or schedule execution after a given delay",
            indicators=["WScript.Sleep", ".setTimeout(", ".setInterval("],
            severity=0,
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)
        if len(self.marks) > 10:
            self.marks = set(list(self.marks)[:10])


class AntiSandboxTimeout(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="antisandbox_timeout",
            description="JavaScript file managed to delay execution until the sandbox timed out",
            indicators=["Script execution timed out after"],
            severity=0,
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)
