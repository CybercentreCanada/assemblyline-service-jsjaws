"""
These are all of the signatures related to running a shell command
"""
from signatures.abstracts import Signature


class RunsShell(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="runs_shell",
            description="JavaScript runs code via shell",
            indicators=["WScript.Shell", ".Run"],
            severity=0
        )

    def process_output(self, output):
        self.check_indicators_in_list(output, match_all=True)


class RunsExecutable(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="runs_executable",
            description="JavaScript runs dropped executable",
            indicators=["WScript.Shell", ".Run", ".exe"],
            severity=0,
            safelist=["cmd.exe"]
        )

    def process_output(self, output):
        self.check_indicators_in_list(output, match_all=True)


class RunsCommandPrompt(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="runs_cmd_prompt",
            description="JavaScript runs Command Prompt via cmd.exe",
            indicators=["WScript.Shell", ".Run", "cmd.exe"],
            severity=0
        )

    def process_output(self, output):
        self.check_indicators_in_list(output, match_all=True)


class RunsPowerShell(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="runs_ps1",
            description="JavaScript runs PowerShell via powershell.exe",
            indicators=["WScript.Shell", ".Run", "powershell.exe"],
            severity=0
        )

    def process_output(self, output):
        self.check_indicators_in_list(output, match_all=True)


class RunsElevatedPowerShell(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="runs_elevated_ps1",
            description="JavaScript runs elevated PowerShell via powershell.exe",
            indicators=["powershell.exe", "-ExecutionPolicy", "bypass"],
            severity=0
        )

    def process_output(self, output):
        self.check_indicators_in_list(output, match_all=True)


class RunsHiddenPowerShell(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="runs_hidden_ps1",
            description="JavaScript runs PowerShell via powershell.exe in a hidden window",
            indicators=["powershell.exe", "-windowstype", "hidden"],
            severity=0
        )

    def process_output(self, output):
        self.check_indicators_in_list(output, match_all=True)


class RunsNoProfilePowerShell(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="runs_ps1_no_profile",
            description="JavaScript runs PowerShell via powershell.exe with no profile",
            indicators=["powershell.exe", "-noprofile"],
            severity=0
        )

    def process_output(self, output):
        self.check_indicators_in_list(output, match_all=True)
