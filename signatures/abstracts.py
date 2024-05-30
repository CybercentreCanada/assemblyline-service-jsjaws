from re import findall
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
            # For more lines of output, there is a datetime separated by a ]. We do not want the datetime.
            split_line = string.split("] ")
            if len(split_line) == 2:
                string = split_line[1]
            elif len(split_line) > 2:
                string = "] ".join(split_line[1:])

            # If we want to match all indicators in a line and nothing from the safelist is in that line, mark it!
            if (
                match_all
                and all(indicator.lower() in string.lower() for indicator in self.indicators)
                and not any(item.lower() in string.lower() for item in self.safelist)
            ):
                self.add_mark(string)

            # If we only want to match at least one indicator in a line, then mark it!
            if not match_all:
                for indicator in self.indicators:
                    if indicator.lower() in string.lower() and not any(
                        item.lower() in string.lower() for item in self.safelist
                    ):
                        self.add_mark(string)

    @staticmethod
    def check_regex(regex: str, string: str) -> List[str]:
        """
        This method takes a string and looks for if the regex is able to find captures
        :param regex: A regular expression to be applied to the string
        :param string: A line of output
        """
        result = findall(regex, string)
        if len(result) > 0:
            return result
        else:
            return []

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
        if mark:
            if safe_str(mark).strip() not in self.marks:
                # Sometimes lines end with trailing semi-colons and sometimes they do not. These are not unique marks
                if safe_str(mark).strip() + ";" not in self.marks:
                    self.marks.append(safe_str(mark).strip())
        else:
            return False

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
            split_line = string.split("] ")
            if len(split_line) == 2:
                string = split_line[1]

            # If all_indicators
            are_indicators_matched = True
            for all_indicator in all_indicators:
                if are_indicators_matched and all(
                    indicator.lower() in string.lower() for indicator in all_indicator["indicators"]
                ):
                    for any_indicator in any_indicators:
                        if are_indicators_matched and any(
                            indicator.lower() in string.lower() for indicator in any_indicator["indicators"]
                        ):
                            pass
                        else:
                            are_indicators_matched = False
                else:
                    are_indicators_matched = False

            # If no all_indicators
            if not all_indicators:
                for any_indicator in any_indicators:
                    if are_indicators_matched and any(
                        indicator.lower() in string.lower() for indicator in any_indicator["indicators"]
                    ):
                        pass
                    else:
                        are_indicators_matched = False

            if are_indicators_matched and not any(item.lower() in string.lower() for item in self.safelist):
                self.add_mark(string)
