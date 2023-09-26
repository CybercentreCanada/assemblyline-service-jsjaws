from re import MULTILINE, Match, Pattern, compile, sub
from typing import Dict, List, Tuple


class VariablesParser:
    """Look for: var1 = var2 + var3 + ..; | var1 = var2;"""

    __concatenated_variable_pattern = (
        r"""(?:[a-zA-Z0-9_]{1,100}\s{0,10}="""
        r"""\s{0,10}(?:[a-zA-Z0-9_]{1,100}\s{0,10}\+\s"""
        r"""{0,10}){1,65}[a-zA-Z0-9_]{2,100}\s{0,10}(?=;))|"""
        r"""(?:[a-zA-Z0-9_]{1,100}\s{0,10}="""
        r"""\s{0,10}[a-zA-Z][a-zA-Z0-9_]{1,100}\s{0,65}(?=;))"""
    )
    __concatPattern: Pattern = compile(__concatenated_variable_pattern, MULTILINE)
    """Look for: var1 = 'some value'; | var1 = "some value";s"""
    __variable_definition = (
        r"""(\s{0,10}(?<!\w)[a-zA-Z0-9_]{1,100}\s{0,10}=\s{0,10}"(.*?)");(?<!(\\";))|"""
        r"""(\s{0,10}(?<!\w)[a-zA-Z0-9_]{1,100}\s{0,10}=\s{0,10}'(.*?)');(?<!(\\';))"""
    )
    __variablesPattern: Pattern = compile(__variable_definition, MULTILINE)
    __PLUS_SIGN = "+"
    __between_quotes = """((?<=('|"|`))(.*)(?=('|"|`)))"""
    __between_quotes_pattern: Pattern = compile(__between_quotes)

    def __init__(self):
        self.variable_lookup: Dict[str, List[str]] = {}
        self.concat_lookup: Dict[str, List[str]] = {}

    def __parse_variable_definition(self, file_data: str) -> None:
        match: Match
        for match in self.__variablesPattern.finditer(file_data):
            self.__add_variable(match.group())

    def generate_lookup_table(self, file_data: str):
        self.__parse_variable_definition(file_data)
        return self.variable_lookup

    def __parse_variable(self, variable: str) -> Tuple[str, str]:
        variable_content = variable.split("=")
        key = self.remove_whitespace(variable_content[0])
        match: Match = self.__between_quotes_pattern.search(variable)
        if match:
            return key, match.group()
        return key, variable_content[-1]

    def __add_variable(self, variable: str) -> None:
        key, value = self.__parse_variable(variable)
        self.variable_lookup[key] = value

    def __parse_concatenated_variables(self, variable: str) -> Tuple[str, List[str], bool]:
        variable_content = variable.split("=")
        variable_name = self.remove_whitespace(variable_content[0])
        vars = variable_content[1]
        variables = []
        """Logic can differ due to us handling both var1=var2 AND var1 = var2+var3+var4"""
        if self.__PLUS_SIGN in variable:
            for variable in vars.split("+"):
                variables.append(self.remove_whitespace(variable))
            return variable_name, variables
        else:
            """Handle the case of a reassignment"""
            return variable_name, [self.remove_whitespace(vars)]

    def __add_concat_variable(self, variable: str) -> None:
        key, value = self.__parse_concatenated_variables(variable)
        self.concat_lookup[key] = value

    def __parse_concat_variable_definition(self, file_data: str) -> None:
        """
        Parsing all variables of the form:
        var1 = var2+var3+var4;
        var1 = var2;
        """
        match: Match
        for match in self.__concatPattern.finditer(file_data):
            self.__add_concat_variable(match.group())

    def remove_whitespace(self, var: str) -> str:
        return sub("\s", "", var)

    def __handle_variation(self, concat_variation: List[str]) -> None:
        variable_keys = self.variable_lookup.keys()
        for iter, variable in enumerate(concat_variation):
            if variable not in variable_keys:
                continue
            concat_variation[iter] = self.variable_lookup[variable]

    def __handle_variation_concat(self, concat_variation: List[str], key) -> None:
        concat_keys = self.concat_lookup.keys()
        for iter, variable in enumerate(concat_variation):
            if variable not in concat_keys:
                continue
            concat_variation[iter] = self.concat_lookup[variable]

    def __assign_strings(self) -> None:
        for key, value in self.concat_lookup.items():
            self.__handle_variation(value)

    def __assign_concats(self) -> None:
        for key, value in self.concat_lookup.items():
            self.__handle_variation_concat(value, key)

    def __get_all_blocks(self) -> List[str]:
        obfuscated_blocks: List[str] = []
        for _, concat_variable in self.concat_lookup.items():
            obfuscated_block: str = ""
            for var in concat_variable:
                """Since a concatenated variable can be made up of concatenated variables"""
                obf_block = ""
                if type(var) == list:
                    try:
                        for var in var:
                            obf_block += var
                    except:
                        pass
                else:
                    obf_block = var
                obfuscated_block += obf_block
            obfuscated_blocks.append(obfuscated_block)
        return obfuscated_blocks

    def reset(self):
        self.variable_lookup = {}
        self.concat_lookup = {}

    def run(self, file_data: str) -> str:
        self.__parse_variable_definition(file_data)
        self.__parse_concat_variable_definition(file_data)
        self.__assign_strings()
        self.__assign_concats()
        return max(self.__get_all_blocks(), key=len)


def grab_longest_string(content: str):
    __between_quotes = """((')(.+)('))"""
    __between_quotes_regex = compile(__between_quotes)
    longest_substring = 0
    longest_substring_index = None
    substrings = __between_quotes_regex.findall(content)
    for index, match in enumerate(substrings):
        if len(match) > longest_substring:
            longest_substring = len(match)
            longest_substring_index = index
    if longest_substring_index is not None:
        return substrings[longest_substring_index][0][1:-1]
    return None
