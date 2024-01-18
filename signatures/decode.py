"""
These are all of the signatures related to decoding
"""
from signatures.abstracts import Signature


class Unescape(Signature):
    # Supported by https://github.com/CYB3RMX/Qu1cksc0pe/blob/ad3105ab9d3363df013ff95bae218f5c374a93fb/Systems/Multiple/malicious_html_codes.json#L27
    # https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/unescape
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="unescape",
            description="JavaScript uses unescape() to decode an encoded string",
            indicators=["unescape"],
            severity=0,
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)


class DecodeURI(Signature):
    # https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/decodeURIComponent
    # https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/decodeURI
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="decode_uri",
            description="JavaScript decodes a Uniform Resource Identifier",
            indicators=["decodeURIComponent(", "decodeURI("],
            severity=0,
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)


class EncodeURI(Signature):
    # https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/encodeURIComponent
    # https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/encodeURI
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="encode_uri",
            description="JavaScript encodes a Uniform Resource Identifier",
            indicators=["encodeURIComponent(", "encodeURI("],
            severity=0,
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)


class SuspiciousUseOfCharCodes(Signature):
    # Inspired by https://github.com/CYB3RMX/Qu1cksc0pe/blob/ad3105ab9d3363df013ff95bae218f5c374a93fb/Systems/Multiple/malicious_html_codes.json#L52C6-L52C18
    # https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/charCodeAt
    # https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/fromCharCode
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="suspicious_char_codes",
            description="JavaScript uses charCodeAt/fromCharCode to obfuscate/de-obfuscate characters",
            indicators=[".charCodeAt(", "fromCharCode("],
            severity=0,
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)


class Base64Decoding(Signature):
    # Supported by https://github.com/CYB3RMX/Qu1cksc0pe/blob/ad3105ab9d3363df013ff95bae218f5c374a93fb/Systems/Multiple/malicious_html_codes.json#L12
    # https://developer.mozilla.org/en-US/docs/Web/API/atob.
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="base64_decoding",
            description="JavaScript uses a common base64 method for decoding characters",
            indicators=["b64toblob(", "atob(", "b64blb(", "FromBase64Transform", "TransformFinalBlock"],
            severity=0,
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
            severity=0,
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
            severity=0,
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
            severity=3,
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)


class SplitReverseJoin(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="split_reverse_join",
            description="JavaScript uses a uncommon method for de-obfuscating a string (split+reverse+join)",
            indicators=['.split("").reverse().join("")'],
            severity=0,
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
            severity=3,
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
            severity=2,
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
            severity=2,
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)


class ObfuscationPrefix(Signature):
    # Inspired by https://github.com/CYB3RMX/Qu1cksc0pe/blob/ad3105ab9d3363df013ff95bae218f5c374a93fb/Systems/Multiple/malicious_html_codes.json#L2
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="_0x_prefix",
            description="The prefix '_0x' in names of variables and functions suggests that obfuscated code exists",
            indicators=["_0x"],
            severity=0,
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)


class ParseIntUsage(Signature):
    # Inspired by https://github.com/CYB3RMX/Qu1cksc0pe/blob/ad3105ab9d3363df013ff95bae218f5c374a93fb/Systems/Multiple/malicious_html_codes.json#L17
    # https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/parseInt
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="parseint_usage",
            description="JavaScript uses parseInt to convert a string to an integer",
            indicators=["parseInt"],
            severity=0,
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)
