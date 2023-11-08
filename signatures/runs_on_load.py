"""
These are all of the signatures related to running a document object on page load
"""
from signatures.abstracts import ANY, Signature


class AppendAndClick(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="append_and_click",
            description="JavaScript appends a child object to the document and clicks it",
            indicators=[".click("],
            severity=0,
        )

    def process_output(self, output):
        indicator_list = [
            {"method": ANY, "indicators": "document.body.appendChild("},
            {"method": ANY, "indicators": self.indicators},
        ]
        self.check_multiple_indicators_in_list(output, indicator_list)
