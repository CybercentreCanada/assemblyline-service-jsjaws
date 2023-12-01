"""
These are all of the signatures related to the presence of suspicious HTML components
"""
from signatures.abstracts import Signature


class IFrameUsage(Signature):
    # Inspired by https://github.com/CYB3RMX/Qu1cksc0pe/blob/ad3105ab9d3363df013ff95bae218f5c374a93fb/Systems/Multiple/malicious_html_codes.json#L22C6-L22C12
    # https://developer.mozilla.org/en-US/docs/Web/HTML/Element/iframe
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="iframe_usage",
            description="Nested browsing context spotted, which could be used for click-jacking or drive-by downloads",
            indicators=["iframe", "HTMLIFrameElement"],
            severity=0,
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)
