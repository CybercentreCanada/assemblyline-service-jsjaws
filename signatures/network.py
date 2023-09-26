"""
These are all of the signatures related to making network requests
"""
from signatures.abstracts import Signature


class PrepareNetworkRequest(Signature):
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
            {"method": "all", "indicators": self.indicators},
        ]
        self.check_multiple_indicators_in_list(output, indicator_list)
