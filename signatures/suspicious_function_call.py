"""
These are all of the signatures related to using suspicious function calls
"""
from signatures.abstracts import Signature


class SuspiciousFunctionCall(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="suspicious_function_call",
            description="JavaScript use a suspicious pattern for evaluation",
            severity=0
        )

    def process_output(self, output):
        suspicious_pattern_regex = r"\w+\[[^\]]+\]\([^)]+\)\([^)]+\)"
        results = []
        for line in output:
            results.extend(self.check_regex(suspicious_pattern_regex, line))

        if len(results) > 0:
            for result in results:
                self.marks.add(f"{result} is evaluated using a suspicious pattern")
