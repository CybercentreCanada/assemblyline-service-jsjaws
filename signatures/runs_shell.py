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
            severity=0
        )

    def process_output(self, output):
        indicator_list = [
            {
                "method": "all",
                "indicators": ["WScript.Shell", ".Exec"]
            },
        ]
        self.check_multiple_indicators_in_list(output, indicator_list)

        indicator_list = [
            {
                "method": "all",
                "indicators": ["WScript.Shell", ".Run"]
            },
        ]
        self.check_multiple_indicators_in_list(output, indicator_list)


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
            indicators=["cmd.exe", "cmd "],
            severity=0
        )

    def process_output(self, output):
        indicator_list = [
            {
                "method": "any",
                "indicators": self.indicators
            },
        ]
        self.check_multiple_indicators_in_list(output, indicator_list)


class RunsPowerShell(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="runs_ps1",
            description="JavaScript runs PowerShell via powershell.exe",
            indicators=["powershell"],
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
            indicators=["powershell", "-exec", "bypass"],
            severity=3
        )

    def process_output(self, output):
        self.check_indicators_in_list(output, match_all=True)


class RunsHiddenPowerShell(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="runs_hidden_ps1",
            description="JavaScript runs PowerShell via powershell.exe in a hidden window",
            indicators=["powershell", "-w", "hidden"],
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
            indicators=["powershell", "-nop"],
            severity=3
        )

    def process_output(self, output):
        self.check_indicators_in_list(output, match_all=True)


class PowerShellDownloader(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="runs_ps1_to_download",
            description="JavaScript runs PowerShell to call out to a URI",
            indicators=["powershell", "http"],
            severity=0
        )

    def process_output(self, output):
        self.check_indicators_in_list(output, match_all=True)
