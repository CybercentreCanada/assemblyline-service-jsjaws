#!/usr/bin/env python
# filename          : GootLoaderAutoJsDecode.py
# description       : GootLoader automatic static JS decoder
# author            : @andy2002a - Andy Morales
# author            : @g0vandS - Govand Sinjari
# date              : 2023-01-13
# updated           : 2023-02-09
# version           : 3.1.1
# usage             : python GootLoaderAutoJsDecode.py malicious.js
# output            : DecodedJsPayload.js_ and GootLoader3Stage2.js_
# py version        : 3
#
# Note: To make JS files readable, you can use CyberChef JavaScript or Generic Code Beautify
#
############################
#
# Legal Notice
#
# Copyright 2023 Mandiant.  All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
#
############################

import re
from codecs import decode, encode
from logging import Logger
from os import SEEK_END, SEEK_SET
from typing import List

from tools.gootloader.utils.variables import *

version_three: bool = False


def defang(input):
    if not input.strip():
        return input
    # most domains/ip/url have a dot, match anything not already in brackets ([^\[])\.([^\]])
    start = input
    end = ""
    ignoreNext = False
    for i,_ in enumerate(input):
        if ignoreNext:
            ignoreNext = False
            continue
        # if input has a single slash, not a double slash, split it at the first one and just escape the first half.
        # this avoids escaping the domains' URI dots, which are always after the first single slash
        if input[i] == '/':
            if (i + 1) < len(input) and input[i + 1] == '/':
                ignoreNext = True
                continue
            start = input[:i]
            end = input[i:]
            break

    result = re.compile("([^\\[])\\.([^\\]])").sub(r"\1[.]\2", start) + end
    # but not all! http://0x7f000001 ([^\[]):([^\]])
    #result = result.replaceAll(new RegExp("([^\\[]):([^\\]])", 'g'), "$1[:]$2");
    result = re.compile("([^\\[]):([^\\]])").sub(r"\1[:]\2", result)
    if result.lower().startswith("http"):
        result = result.replace("https", "hxxps")
        result = result.replace("http", "hxxp")
    return result


def clean_padding(file_data:str):
    """
    I want to remove all the letters | numbers that appear in larger groups followed with a ;
    However, before doing so, I'll remove 95% of the bottom section of the file.
    """
    file_data = file_data[0: int(len(file_data) * 0.05)]
    padded_letters_rule = "[a-zA-Z]{300,};?"
    padded_number_rule = "[0-9]{15,};?"
    padding = f"{padded_letters_rule}|{padded_number_rule}"

    matches = re.findall(padding, file_data)
    for match in matches:
        file_data = file_data.replace(match, "")
    return file_data


def convert_concat_to_string(input_concat_matches, input_variable_dict, no_equals=False):
    concatenated_results: List[str] = []
    if no_equals:
        dummy_equals = 'dummy='+input_concat_matches.replace('(','').replace(')','')
        input_concat_matches = [dummy_equals]

    for index, concat_item in enumerate(input_concat_matches):
        # Remove any unwanted characters and split on '='
        split_item = concat_item.replace(';','').replace(' ','').replace('\t','').split('=')

        current_line_string = ''
        for additionItem in split_item[1].split('+'):
            try:
                # look up the items in the dict and join them together
                current_line_string += input_variable_dict[additionItem]
            except Exception as e:
                # probably a junk match
                continue
            input_variable_dict.update({split_item[0]:current_line_string})
        concatenated_results.append(current_line_string)
    """
    Instead of relying on the fact the variable with the most variables concatenated is the longest string.
    Lets perform the check once we've formed all the combinations and we can ensure it is the case
    """
    return max(concatenated_results, key=len).encode('raw_unicode_escape').decode('unicode_escape')


def deobfuscate(obfuscated_string):
    plaintext: str = ""
    obfuscated_string = decode(encode(obfuscated_string, 'latin-1', 'backslashreplace'), 'unicode-escape')
    for counter in range(len(obfuscated_string)):
        decoded_char = obfuscated_string[counter]
        if counter % 2:
            plaintext = plaintext + decoded_char
        else:
            plaintext = decoded_char + plaintext
    return plaintext


def remainder(v1, v2, v3):
    """
    # V3 Decoding scripts converted from their JS versions
    """
    if(v3 % 2): rtn = v1+v2
    else: rtn = v2+v1
    return rtn


def js_substring(inputStr, idx1):
    """Use this odd format of substring so that it matches the way JS works"""
    return inputStr[idx1:(idx1+1)]


def work_function(inputStr):
    outputStr = ''
    for i in range(len(inputStr)):
        var1 = js_substring(inputStr,i)
        outputStr = remainder(outputStr, var1, i)
    return outputStr


def check_file_stage(top_lines: str, path: str, log: Logger):
    goot3linesRegex = """//GOOT3"""
    goot3linesPattern = re.compile(goot3linesRegex, re.MULTILINE)
    gootloader3_sample = False

    if goot3linesPattern.match(top_lines):
        log('GootLoader Obfuscation Variant 3.0 detected')
        gootloader3_sample = True

    return gootloader3_sample


def is_powershell(file_data):
    powershell = "powershell"
    cleaned = file_data.replace("'+'",'').replace("')+('",'').replace("+()+",'')
    match = re.search(powershell, cleaned, re.IGNORECASE)
    return True if match else False


def check_file_size(file_handle):
    """Checks to see if the contents surpass 10MB"""
    file_position = file_handle.tell()
    file_handle.seek(0, SEEK_END)
    size = file_handle.tell()
    file_handle.seek(file_position, SEEK_SET)
    if(size >= (2**20 * 10)): return True


def save_file(output_filename, output_code, log: Logger):
    """Save the output file - We may need it for the second iteration"""
    log(f'Script output Saved to: {output_filename}')
    log(f'The script will now attempt to deobfuscate the {output_filename} file.')
    out_file = open(output_filename, "w")
    out_file.write(output_code)
    out_file.close()


def goot_decode_modified(path: str, unsafe_uris = False, payload_path = None, stage2_path = None, log: Logger = print):
    variables = VariablesParser()                        #Utility class to parse variables from JScript

    gootloader3_sample = False
    output_filename: str = ""

    file = open(path, mode="r", encoding="utf-8")        # Open File

    file_top_lines = ''.join(file.readlines(5))
    gootloader3_sample = check_file_stage(file_top_lines, path, log)

    file.seek(0)                                         #Reset the cursor
    file_data = file.read()                              #Read the file contents
    obfuscated_round_one = variables.run(file_data)

    if(check_file_size(file)):
        """Handles cleaning the log files"""
        file_data = clean_padding(file_data)
    file.close()

    if not obfuscated_round_one:
        return

    first_round_result = deobfuscate(obfuscated_round_one)
    longest_string = grab_longest_string(first_round_result)
    second_round_result = deobfuscate(longest_string)

    if second_round_result.startswith('function'):
        log('GootLoader Obfuscation Variant 3.0 sample detected.')
        """
        Grab all the relevant variables from the sample, that'll be needed to build the obfuscated blocks.
        """
        v3_work_vars_pattern = re.compile('''(?:\((?:[a-zA-Z0-9_]{2,}\s{0,}\+\s{0,}){1,}[a-zA-Z0-9_]{2,}\s{0,}\))''') # Find: (var1+var2+var3)
        v3_work_vars = v3_work_vars_pattern.search(second_round_result)[0]

        vars_dict = variables.generate_lookup_table(file_data)
        second_stage_jscript = work_function(convert_concat_to_string(v3_work_vars, vars_dict, True))

        string_variable_pattern = re.compile('''([a-zA-Z0-9_]{2,}\s{0,}=('|").*?('|");)(?=([a-zA-Z0-9_]{2,}\s{0,}=)|function)''') # Find: var='xxxxx';[var2=|function]
        string_variable_new_line = re.sub(string_variable_pattern, r'\n\1\n', second_stage_jscript)

        """
        Get all the var concat on their own line
        """
        string_concat_pattern = re.compile('''([a-zA-Z0-9_]{2,}\s{0,}=\s{0,}(?:[a-zA-Z0-9_]{2,}\s{0,}\+\s{0,}){1,}[a-zA-Z0-9_]{2,}\s{0,};)''') # Find: var1 = var2+var3
        string_concat_new_line = re.sub(string_concat_pattern, r'\n\1\n', string_variable_new_line)

        """
        Attempt to find the last variable and add a tab in front of it.
        This search is imperfect since the line could be shorter than what this regex picks up.
        """
        final_string_concat = re.compile('''([a-zA-Z0-9_]{2,}\s{0,}=\s{0,}(?:[a-zA-Z0-9_]{2,}\s{0,}\+\s{0,}){5,}[a-zA-Z0-9_]{2,}\s{0,};)''') # Find: var0 = var1+var2+var3+var4+var5+var6
        final_str_concat_new_line = re.sub(final_string_concat, r'\n\t\1\n', string_concat_new_line)

        """
        Put 1:1 variables on their own lines & put the long digits on their own line.
        """
        str_var_to_var = re.compile('''((?:\n|^)[a-zA-Z0-9_]{2,}\s{0,}=\s{0,}[a-zA-Z0-9_]{2,};)''')# Find: var = var2;
        str_var_to_var_new_line = re.sub(str_var_to_var, r'\n\1\n', final_str_concat_new_line)
        str_long_digit = re.compile(''';(\d{15,};)''') # Find: ;216541846845465456465121312313221456456465;
        final_regex = re.sub(str_long_digit, r';\n\1_\n', str_var_to_var_new_line)

        """
        Build the text file, and add the GOOT3 header.
        The header will allow us to direct the code in the correct path for the next iteration.
        """
        output_code = '//GOOT3\n'                      #The file header which will be needed for the next iteration
        for line in final_regex.splitlines():
            if line.strip():                           #Clean up the empty strings
                output_code += (line+'\n')             #Generate the output code to be written to disk
        if not stage2_path:
            output_filename = 'GootLoader3Stage2.js_'
        else:
            output_filename = stage2_path
        save_file(output_filename, output_code, log)
        return True, "", ""

    else:
        """To provide support for the log file written to disk for persistance the or is_powershell has been added"""
        if gootloader3_sample or is_powershell(second_round_result):
            output_code = second_round_result.replace("'+'",'').replace("')+('",'').replace("+()+",'')
            version_three_domain_regex = re.compile('''(?:(?:https?):\/\/)[^\[|^\]|^\/|^\\|\s]*\.[^'"]+''')
            malicious_domains = re.findall(version_three_domain_regex, output_code)
        else:
            """Otherwise handle second version domain extraction"""
            output_code = second_round_result
            version_two_domain_regex = re.compile(r'(.*)(\[\".*?\"\])(.*)')
            domains_match = version_two_domain_regex.search(second_round_result)[2]
            malicious_domains = domains_match.replace("[","").replace("]","").replace("\"","").replace("+(","").replace(")+","").split(',')

        if not payload_path:
            output_filename = 'DecodedJsPayload.js_'
        else:
            output_filename = payload_path

        # debugging
        # log('\nScript output Saved to: %s\n' % output_filename)

        gootloader_domains: List[str] = []
        for dom in malicious_domains:
            if not unsafe_uris:
                gootloader_domains.append(defang(dom))
            else:
                gootloader_domains.append(dom)

        # debugging
        # domains_as_string = "\n".join(gootloader_domains)
        # log(f'\nMalicious Domains: \n\n{domains_as_string}')

    """Save the output file - We may need it for the second iteration"""
    save_file(output_filename, output_code, log)
    return False, gootloader_domains, output_code
