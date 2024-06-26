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


class DocumentWrite(Signature):
    # Supported by https://github.com/CYB3RMX/Qu1cksc0pe/blob/ad3105ab9d3363df013ff95bae218f5c374a93fb/Systems/Multiple/malicious_html_codes.json#L42
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="document_write",
            description="Object(s) are written to the DOM",
            indicators=["document", ".write(content)"],
            severity=0,
        )

    def process_output(self, output):
        self.check_indicators_in_list(output, match_all=True)


class ExecCommandUsage(Signature):
    # Inspired by https://github.com/target/strelka/blob/3439953e6aa2dafb68ea73c3977da11f87aeacdf/src/python/strelka/scanners/scan_javascript.py#L34
    # https://developer.mozilla.org/en-US/docs/Web/API/document/execCommand
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="execcommand_usage",
            description="Executes command, possibly related to clipboard access, or editing forms and documents.",
            indicators=["execCommand("],
            severity=0,
        )

    def process_output(self, output):
        self.check_indicators_in_list(output, match_all=True)
