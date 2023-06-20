from re import compile, MULTILINE, Pattern, Match, search, sub
from typing import List, Dict, Tuple
        

class VariablesParser:
    __concatenated_variable_pattern = ("""(?:[a-zA-Z0-9_]{2,}\s{0,}=\s{0,}(?:[a-zA-Z0-9_]{2,}\s{0,}\+\s{0,}){1,}[a-zA-Z0-9_]{2,}\s{0,}(?=;))|"""                            # Find: var1 = var2+var3+var4;
                                       """(?:[a-zA-Z0-9_]{2,}\s{0,}=\s{0,}[a-zA-Z][a-zA-Z0-9_]{1,}\s{0,}(?=;))""")                                                          # Find: var1 = var2;
    __concatPattern: Pattern = compile(__concatenated_variable_pattern, MULTILINE)


    __variable_definition = ("""\s*(?<!\w)[a-zA-Z0-9_]{2,}\s*=\s*\\(*'.*?(((?<!\\\)'\\)*;))|"""                                                                             # Find: var='str';
                             """\s*(?<!\w)[a-zA-Z0-9_]{2,}\s*=\s*\\(*".*?(((?<!\\\)"\\)*;))"""                                                                              # Find: var = "str";
                            )                                                                             
    __variablesPattern: Pattern = compile(__variable_definition, MULTILINE)
    

    __PLUS_SIGN = "+"
    __between_quotes = '''((?<=('|"|`))(.*)(?=('|"|`)))'''
    __between_quotes_pattern: Pattern = compile(__between_quotes)


    def __init__(self):
        self.variable_lookup: Dict[str, List[str]] = {}
        self.concat_lookup: Dict[str, List[str]] = {}


    def __parse_variable_definition(self, file_data:str) -> None:
        """
        We'll first parse out all the variables defined. 
        These will be the building blocks to generate all possible ciphers once we parse all the concatenated variables.

        The scenario of multiple variable redefinition may occur, therefore all will be stored.

        Find: var='str';
        Find: var = "str";
        Find: var = 1234;
        """
        match: Match
        for match in self.__variablesPattern.finditer(file_data):
            self.__add_variable(match.group())


    def generate_lookup_table(self, file_data: str):
        self.__parse_variable_definition(file_data)
        return self.variable_lookup


    def __parse_variable(self, variable:str) -> Tuple[str, str]:
        variable_content = variable.split("=")
        key = self.remove_whitespace(variable_content[0])
        match: Match = self.__between_quotes_pattern.search(variable)
        if(match):
            return key, match.group()
        return key, variable_content[-1]
    


    def __add_variable(self, variable:str) -> None:
        key, value = self.__parse_variable(variable)
        self.variable_lookup[key] = value



    def __parse_concatenated_variables(self, variable:str) -> Tuple[str, List[str], bool]:
        variable_content = variable.split("=")
        variable_name = self.remove_whitespace(variable_content[0])
        vars = variable_content[1]
        
        variables = []
        """Logic can differ due to us handling both var1=var2 AND var1 = var2+var3+var4"""
        if(self.__PLUS_SIGN in variable):
            for variable in (vars.split("+")):
                variables.append(self.remove_whitespace(variable))
            return variable_name, variables
        else: 
            """Handle the case of a reassignment"""
            return variable_name, [self.remove_whitespace(vars)]



    def __add_concat_variable(self, variable:str) -> None:
        key, value = self.__parse_concatenated_variables(variable)
        self.concat_lookup[key] = value


    def __parse_concat_variable_definition(self, file_data:str) -> None:
        """
        Parsing all variables of the form:
        var1 = var2+var3+var4;
        var1 = var2;
        """
        match: Match
        for match in self.__concatPattern.finditer(file_data):
            self.__add_concat_variable(match.group())


    def remove_whitespace(self, var:str) -> str:
        return sub('\s', "", var)



    def __handle_variation(self, concat_variation: List[str]) -> None:
        variable_keys = self.variable_lookup.keys()
        for iter, variable in enumerate(concat_variation):
            if(not variable in variable_keys): continue
            concat_variation[iter] = self.variable_lookup[variable]



    def __handle_variation_concat(self, concat_variation: List[str], key) -> None:
        concat_keys = self.concat_lookup.keys() 
        for iter, variable in enumerate(concat_variation):
            if(not variable in concat_keys): continue
            concat_variation[iter] = self.concat_lookup[variable]



    def __assign_strings(self) -> None:
        for key, value in self.concat_lookup.items():
            self.__handle_variation(value)




    def __assign_concats(self) -> None:
        for key, value in self.concat_lookup.items():
            self.__handle_variation_concat(value, key)



    def __build_obfuscated_blocks(self) -> List[str]:
        obfuscated_blocks: List[str] = []
        for _, value in self.concat_lookup.items():
            try:
                obfuscated_block = ""
                for concat_variable in value:
                    if(not type(concat_variable) == list): continue
                    for variable in concat_variable:
                        obfuscated_block+=variable
            except: pass
            obfuscated_blocks.append(obfuscated_block)
        return obfuscated_blocks
    


    def reset(self):
        self.variable_lookup: Dict[str, List[str]] = {}
        self.concat_lookup: Dict[str, List[str]] = {}



    def run(self, file_data: str) -> str:    
        self.__parse_variable_definition(file_data)
        self.__parse_concat_variable_definition(file_data)

        self.__assign_strings()
        self.__assign_concats()  
        return max(self.__build_obfuscated_blocks(), key=len)



def grab_longest_string(content:str):
    """
    Description
    -----------
    Given some string, we'll return the largest substring found within
    """
    __between_quotes = '''((')(.+)('))'''
    __between_quotes_regex = compile(__between_quotes)

    longest_substring = 0
    longest_substring_index = None

    substrings = __between_quotes_regex.findall(content)
    for index, match in enumerate(substrings):
        if(len(match) > longest_substring):
            longest_substring = len(match)
            longest_substring_index = index

    if(longest_substring_index != None): 
        try: 
            #Could make use of groups to avoid this check.
            return substrings[longest_substring_index][0][1:-1]     
        except: return None
    return None

