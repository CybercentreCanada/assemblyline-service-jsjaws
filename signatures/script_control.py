from signatures.abstracts import Signature


class ScriptControl(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="script_control",
            description="JavaScript uses MSScriptControl to run a script",
            indicators=["WScript.CreateObject", "MSScriptControl.ScriptControl"],
            severity=1
        )

    def process_output(self, output):
        self.check_indicators_in_list(output, match_all=True)


class ScriptControlVBS(Signature):
    def __init__(self):
        super().__init__(
            heuristic_id=3,
            name="script_control_vbs",
            description="JavaScript uses MSScriptControl to write and run a VBScript",
            indicators=["MSScriptControl.ScriptControl", ".Language", "VBScript"],
            severity=2
        )

    def process_output(self, output):
        self.check_indicators_in_list(output, match_all=True)

