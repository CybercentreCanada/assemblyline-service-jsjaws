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
            severity=5,
        )

    def process_output(self, output):
        # Example of this is word1[word2](word1[word3])(word4)
        suspicious_pattern_regex = r"(?P<word1>\w{1,20})\[[^\]]{1,20}\]\((?P=word1)\[[^\]]{1,20}\]\)\([^)]{1,20}\)"
        results = []
        for line in output:
            results.extend(self.check_regex(suspicious_pattern_regex, line))

        if len(results) > 0:
            for result in results:
                if f"{result} is evaluated using a suspicious pattern" not in self.marks:
                    self.marks.append(f"{result} is evaluated using a suspicious pattern")
