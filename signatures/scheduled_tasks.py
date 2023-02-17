"""
These are all of the signatures related to using scheduled tasks
"""
from signatures.abstracts import Signature


class ScheduledTask(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="scheduled_task",
            description="JavaScript creates an ActiveXObject to schedule a task",
            indicators=["Schedule.Service"],
            severity=0
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)