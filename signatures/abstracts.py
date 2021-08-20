from typing import Optional, List, Tuple, Set
from re import findall
from assemblyline.common.str_utils import safe_str


class Signature:
    def __init__(self, heuristic_id: int = None, name: str = None, description: str = None, ttp: List[str] = None,
                 families: List[str] = None, indicators: List[str] = None, severity: int = None,
                 safelist: List[str] = None):
        self.heuristic_id: Optional[int] = heuristic_id
        self.name: Optional[str] = name
        self.description: Optional[str] = description
        self.ttp: List[str] = [] if ttp is None else ttp
        self.families: List[str] = [] if families is None else families
        self.indicators: List[str] = [] if indicators is None else indicators
        self.marks: Set[str] = set()
        self.severity: int = 0 if severity is None else severity
        self.safelist: List[str] = [] if safelist is None else safelist

    def check_indicators_in_list(self, list_of_strings: List[str], match_all: bool = False) -> None:
        """
        @param match_all: All indicators must be found in a single line for a mark to be added
        """
        for string in list_of_strings:
            split_line = string.split(" - ")
            if len(split_line) == 2:
                string = split_line[1]

            if match_all and all(indicator.lower() in string.lower() for indicator in self.indicators) and \
                    not any(item.lower() in string.lower() for item in self.safelist):
                self.marks.add(safe_str(string))

            if not match_all:
                for indicator in self.indicators:
                    if indicator.lower() in string.lower():
                        self.marks.add(safe_str(string))

    @staticmethod
    def check_regex(regex: str, string: str) -> Tuple[bool, List[str]]:
        result = findall(regex, string)
        if len(result) > 0:
            return True, result
        else:
            return False, []

    def process_output(self, output):
        raise NotImplementedError
