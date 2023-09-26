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
            severity=0,
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)


class RunsScheduledTask(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="runs_schtasks_via_cmd_prompt",
            description="JavaScript runs Scheduled Task utility via cmd.exe",
            indicators=["cmd.exe", "schtasks"],
            severity=0,
        )

    def process_output(self, output):
        self.check_indicators_in_list(output, match_all=True)
