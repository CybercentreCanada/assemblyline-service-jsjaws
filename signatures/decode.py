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
            indicators=["b64toblob(", "atob(", "b64blb(", "FromBase64Transform", "TransformFinalBlock"],
            severity=0
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)


class Obfuscation(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="obfuscation",
            description="JavaScript uses a commonly-seen method for de-obfuscating a string",
            indicators=["reverse("],
            severity=0
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)


class CryptoJSObfuscation(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="crypto_js_obfuscation",
            description="JavaScript uses CryptoJS for obfuscating/de-obfuscating a string",
            indicators=["CryptoJS"],
            severity=0
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)


class NestedAtoB(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="nested_atob",
            description="JavaScript uses nested atob() calls for decoding",
            indicators=["atob(atob("],
            severity=3
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)


class SplitReverseJoin(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="split_reverse_join",
            description="JavaScript uses a uncommon method for de-obfuscating a string (split+reverse+join)",
            indicators=[".split(\"\").reverse().join(\"\")"],
            severity=3
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)


class WriteBase64ContentFromElement(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="write_base64_content_from_element",
            description="JavaScript writes content to the DOM by base64-decoding a value from an element",
            indicators=["document.write(atob(document.getElementById("],
            severity=3
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)


class Base64EncodedURL(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="base64_encoded_url",
            description="JavaScript uses atob to decode a base64-encoded URL",
            # Directly related to the ATOB_URI_REGEX constant!
            indicators=["atob was seen decoding a URI:"],
            severity=2
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)


class Base64Redirect(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="base64_redirect",
            description="JavaScript uses atob to decode a base64-encoded URL then redirect to it",
            indicators=["window.location.replace(atob("],
            severity=2
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)
