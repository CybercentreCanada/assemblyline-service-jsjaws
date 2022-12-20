"""
These are all of the signatures related to running a shell command
"""
from signatures.abstracts import Signature


class CreatesWshObject(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="creates_wsh_object",
            description="JavaScript creates a new Windows Scripting Host Shell Object",
            indicators=["new WScript.Shell"],
            severity=0
        )

    def process_output(self, output):
        self.check_indicators_in_list(output, match_all=True)


class AccessWshEnv(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="access_wsh_env",
            description="JavaScript accesses the WSH Environment",
            indicators=["new WshEnvironment"],
            severity=0
        )

    def process_output(self, output):
        self.check_indicators_in_list(output, match_all=True)


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


class RunsShellApplication(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="runs_shell_application",
            description="JavaScript runs code via shell application",
            indicators=["Shell.Application", ".ShellExecute"],
            severity=1
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
            severity=3,
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
