import re
from typing import Any, Dict, List, Optional, Union

from assemblyline.common.str_utils import safe_str

ANY = "any"
ALL = "all"


class Signature:
    """
    This Signature class represents an abstract signature which can be used for scoring and adding additional details
    to heuristics
    """

    def __init__(
        self,
        heuristic_id: int = None,
        name: str = None,
        description: str = None,
        ttp: List[str] = None,
        families: List[str] = None,
        indicators: List[str] = None,
        severity: int = None,
        safelist: List[str] = None,
    ):
        """
        This method instantiates the base Signature class and performs some validtion checks
        :param heuristic_id: The ID of the heuristic that is associated with this signature
        :param name: The name of the signature
        :param description: The description of the signature
        :param ttp: The ATT&CK IDs of the signature
        :param families: The malware families that this signature is known to be associated with
        :param indicators: A list of strings where each string is an indicator of behaviour that we should look out for
        :param severity: The severity of the signature with regards to if the behaviour is malicious or not
        The severities are as follows:
        0: Informational
        1: Suspicious
        2: Highly Suspicious
        3: Malware
        :param safelist: The safelist that will contain strings that are considered "safe" and
        aim to prevent false positives
        """
        self.heuristic_id: Optional[int] = heuristic_id
        self.name: Optional[str] = name
        self.description: Optional[str] = description
        self.ttp: List[str] = [] if ttp is None else ttp
        self.families: List[str] = [] if families is None else families
        self.indicators: List[str] = [] if indicators is None else indicators

        if severity is None:
            self.severity: int = 0
        elif severity < 0:
            self.severity: int = 0
        elif severity > 3:
            self.severity: int = 3
        else:
            self.severity: int = severity

        self.safelist: List[str] = [] if safelist is None else safelist

        # These are the lines of code from the sandbox that reflect when an indicator has been found
        self.marks: List[str] = list()

    def check_indicators_in_list(self, output: List[str], match_all: bool = False) -> None:
        """
        This method takes a list of strings (output from MalwareJail) and looks for indicators in each line
        :param output: A list of strings where each string is a line of stdout from the MalwareJail tool
        :param match_all: All indicators must be found in a single line for a mark to be added
        """
        for string in output:
            string = self.remove_timestamp(string)
            lower = string.lower()
            any_all = all if match_all else any
            # If we match indicators in a line and nothing from the safelist is in that line, mark it!
            if any_all(indicator.lower() in lower for indicator in self.indicators) and not any(
                item.lower() in lower for item in self.safelist
            ):
                self.add_mark(string)

    @staticmethod
    def check_regex(regex: str, string: str) -> List[str]:
        """
        This method takes a string and looks for if the regex is able to find captures
        :param regex: A regular expression to be applied to the string
        :param string: A line of output
        """
        return re.findall(regex, string)

    def process_output(self, output: List[str]):
        """
        Each signature must override this method
        """
        raise NotImplementedError

    def add_mark(self, mark: Any) -> bool:
        """
        This method adds a mark to a list of marks, after making it safe
        :param mark: The mark to be added
        :return: A boolean indicating if the mark was added
        """
        if not mark:
            return False
        mark = safe_str(mark).strip()
        if mark not in self.marks and mark + ";" not in self.marks:
            # Sometimes lines end with trailing semi-colons and sometimes they do not. These are not unique marks
            self.marks.append(mark)
            return True
        return False

    @staticmethod
    def remove_timestamp(line: str) -> str:
        """Remove the timestamp at the start of an output line."""
        # For more lines of output, there is a datetime separated by a ]. We do not want the datetime.
        return line.split("] ", 1)[-1]

    def check_multiple_indicators_in_list(self, output: List[str], indicators: List[Dict[str, List[str]]]) -> None:
        """
        This method checks for multiple indicators in a list, with varying degrees of inclusivity
        :param output: A list of strings where each string is a line of stdout from the MalwareJail tool
        :param indicators: A list of dictionaries which represent indicators and how they should be matched
        :return: None
        """
        if not indicators:
            return

        all_indicators: List[Dict[str, Union[str, List[str]]]] = [
            indicator for indicator in indicators if indicator["method"] == ALL
        ]
        any_indicators: List[Dict[str, Union[str, List[str]]]] = [
            indicator for indicator in indicators if indicator["method"] == ANY
        ]

        for string in output:
            # For more lines of output, there is a datetime separated by a ]. We do not want the datetime.
            string = self.remove_timestamp(string)
            lower = string.lower()

            # If all_indicators
            are_indicators_matched = True
            for all_indicator in all_indicators:
                if not all(indicator.lower() in lower for indicator in all_indicator["indicators"]):
                    are_indicators_matched = False
                    break

            if are_indicators_matched:
                for any_indicator in any_indicators:
                    if not any(indicator.lower() in lower for indicator in any_indicator["indicators"]):
                        are_indicators_matched = False
                        break

            if are_indicators_matched and not any(item.lower() in lower for item in self.safelist):
                self.add_mark(string)
