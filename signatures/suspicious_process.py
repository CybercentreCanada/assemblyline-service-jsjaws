"""
These are all of the signatures related to the presence of suspicious processes
"""
from signatures.abstracts import Signature


class SuspiciousProcess(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="suspicious_process",
            description="JavaScript uses a suspicious process",
            indicators=["winmgmts", "uneval(", "new Worker("],
            severity=0,
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)


class EvalUsage(Signature):
    # Inspired by https://github.com/CYB3RMX/Qu1cksc0pe/blob/ad3105ab9d3363df013ff95bae218f5c374a93fb/Systems/Multiple/malicious_html_codes.json#L7
    # https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval
    # https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_eval!
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="eval_usage",
            description="Executing JavaScript from a string is an enormous security risk. It is far too easy for a "
            "bad actor to run arbitrary code when you use eval()",
            indicators=["eval("],
            severity=0,
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)
