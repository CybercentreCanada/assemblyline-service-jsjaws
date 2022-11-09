"""
These are all of the signatures related to decoding
"""
from signatures.abstracts import Signature


class Unescape(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="unescape",
            description="JavaScript uses unescape() to decode an encoded string",
            indicators=["unescape"],
            severity=0
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)


class SuspiciousUseOfCharCodes(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="suspicious_char_codes",
            description="JavaScript uses charCodeAt() obfuscate/de-obfuscate characters",
            indicators=[".charCodeAt("],
            severity=0
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)


class Base64Decoding(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="base64_decoding",
            description="JavaScript uses a common base64 method for decoding characters",
            indicators=["reverse(", "b64toblob(", "atob("],
            severity=0
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)
