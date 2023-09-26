"""
These are all of the signatures related to blob usage
"""
from signatures.abstracts import Signature


class CreatesBlob(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="creates_blob",
            description="JavaScript creates a Blob object",
            indicators=["new Blob(", "new File("],
            severity=0,
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)


class CreatesObjectURL(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="creates_object_url",
            description="JavaScript creates an object URL with a blob",
            indicators=["createObjectURL("],
            severity=0,
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)


class GetBytes(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="gets_bytes",
            description="JavaScript accesses byte blob",
            indicators=["GetBytes", "GetByteCount"],
            severity=0,
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)
