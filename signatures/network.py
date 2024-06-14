"""
These are all of the signatures related to making network requests
"""

from signatures.abstracts import ALL, Signature


class PrepareNetworkRequest(Signature):
    # Supported by https://github.com/CYB3RMX/Qu1cksc0pe/blob/ad3105ab9d3363df013ff95bae218f5c374a93fb/Systems/Multiple/malicious_html_codes.json#L47
    # Supported by https://github.com/target/strelka/blob/3439953e6aa2dafb68ea73c3977da11f87aeacdf/src/python/strelka/scanners/scan_javascript.py#L36
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="prepare_network_request",
            description="JavaScript prepares a network request",
            indicators=[".setRequestHeader(", "User-Agent", "XMLHttpRequest("],
            severity=0,
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)


class NetworkRequest(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="network_request",
            description="JavaScript sends a network request",
            indicators=[".send()"],
            severity=0,
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)


class AJAXNetworkRequest(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="ajax_network_request",
            description="JavaScript sends a network request via AJAX and jQuery",
            indicators=["$.ajax("],
            severity=0,
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)


class JQueryNetworkRequest(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="jquery_network_request",
            description="JavaScript sends a network request via jQuery",
            indicators=["$.post(", "$.getJSON("],
            severity=0,
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)


class GeoIPServiceRequest(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="geoip_service_request",
            description="A domain associated with GeoIP services was observed",
            indicators=["GeoIP service"],
            severity=0,
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)


class TelegramExfil(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="telegram_exfil",
            description="An outgoing request was made to Telegram",
            indicators=["XMLHttpRequest", ".open(", "api.telegram.org"],
            severity=3,
        )

    def process_output(self, output):
        indicator_list = [
            {"method": ALL, "indicators": self.indicators},
        ]
        self.check_multiple_indicators_in_list(output, indicator_list)


class WebSocketUsage(Signature):
    # Inspired by https://github.com/target/strelka/blob/3439953e6aa2dafb68ea73c3977da11f87aeacdf/src/python/strelka/scanners/scan_javascript.py#L40
    # https://developer.mozilla.org/en-US/docs/Web/API/WebSocket
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="websocket_usage",
            description="WebSocket object was used for communicating with a server",
            indicators=["WebSocket("],
            severity=0,
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)
