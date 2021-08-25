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
            severity=1
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
            severity=1
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)