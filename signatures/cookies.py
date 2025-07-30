"""
These are all of the signatures related to cookie harvesting
"""

from signatures.abstracts import Signature


class CookieHarvesting(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="cookie_harvesting",
            description="JavaScript attempts to harvest cookies",
            indicators=["chrome.cookies.getAll"],
            severity=0,
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)
