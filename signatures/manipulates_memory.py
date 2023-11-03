"""
These are all of the signatures related to manipulating memory
"""
from signatures.abstracts import Signature


class MemoryStream(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="memory_stream",
            description="JavaScript uses a MemoryStream object to manipulate memory",
            indicators=["MemoryStream"],
            severity=0,
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)


class ReflectiveCodeLoading(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="reflective_code_loading",
            description="JavaScript uses classes found in .NET Runtime Assembly",
            indicators=["Deserialize_2(", "DynamicInvoke("],
            severity=3,
        )

    def process_output(self, output):
        indicator_list = [
            {"method": "any", "indicators": self.indicators},
        ]
        self.check_multiple_indicators_in_list(output, indicator_list)
