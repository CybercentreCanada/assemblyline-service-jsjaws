import re
import tempfile
from base64 import b64decode
from binascii import Error as BinasciiError
from glob import glob
from hashlib import sha256
from inspect import getmembers, isclass
from io import BytesIO
from json import JSONDecodeError, dumps, load, loads
from os import environ, listdir, mkdir, path
from pkgutil import iter_modules
from subprocess import PIPE, Popen, TimeoutExpired
from sys import modules
from threading import Thread
from time import sleep, time
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from assemblyline.common import forge
from assemblyline.common.digests import get_sha256_for_file
from assemblyline.common.entropy import calculate_partition_entropy
from assemblyline.common.hexdump import load as hexload
from assemblyline.common.identify import CUSTOM_BATCH_ID, CUSTOM_PS1_ID
from assemblyline.common.str_utils import safe_str, truncate
from assemblyline.common.uid import get_id_from_data
from assemblyline_service_utilities.common.dynamic_service_helper import (
    COMMON_FP_DOMAINS,
    OntologyResults,
    extract_iocs_from_text_blob,
)
from assemblyline_service_utilities.common.extractor.base64 import BASE64_RE
from assemblyline_service_utilities.common.safelist_helper import is_tag_safelisted
from assemblyline_service_utilities.common.tag_helper import add_tag
from assemblyline_v4_service.common.api import ServiceAPIError
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import (
    Heuristic,
    KVSectionBody,
    Result,
    ResultGraphSection,
    ResultMultiSection,
    ResultSection,
    ResultTableSection,
    ResultTextSection,
    TableRow,
    TextSectionBody,
)
from assemblyline_v4_service.common.utils import PASSWORD_WORDS, extract_passwords
from bs4 import BeautifulSoup
from bs4.element import Comment, ResultSet, Tag
from dateutil.parser import parse as dtparse
from multidecoder.decoders.network import find_urls, is_domain, is_url
from multidecoder.decoders.shell import find_powershell_strings, get_powershell_command
from requests import get
from tinycss2 import parse_stylesheet
from yaml import safe_load as yaml_safe_load

import signatures
from signatures.abstracts import Signature
from tools import tinycss2_helper
from tools.gootloader.run import run as gootloader_run
from yara import Error as YARAError
from yara import compile as yara_compile

# Execution constants

# Default value for the maximum number of files found in the "payload" folder that MalwareJail creates, to be extracted
MAX_PAYLOAD_FILES_EXTRACTED = 50

# The SHA256 representation of the "Resource Not Found" response from MalwareJail that occurs
# when we pass the --h404 arg
RESOURCE_NOT_FOUND_SHA256 = "85658525ce99a2b0887f16b8a88d7acf4ae84649fa05217caf026859721ba04a"

# The SHA256 representation when MalwareJail creates a fake file when _download is set to "No"
FAKE_FILE_CONTENT = "5110232a47fc52354ed061b5e29979f4497ab2d3a3a402ad74f194acedfddad0"

# The string used in file contents to separate code dynamically created by JsJaws and the original script
DIVIDING_COMMENT = "// This comment was created by JsJaws"

# Static path to the system safelist file
SAFELIST_PATH = "al_config/system_safelist.yaml"

# We do not want to dynamically add these attributes to HTML elements
SAFELISTED_ATTRS_TO_POP = {
    "link": ["href"],
    "svg": ["xmlns"],
}

# Signature score translations
TRANSLATED_SCORE = {
    0: 10,  # Informational (0-24% hit rate)
    1: 100,  # On the road to being suspicious (25-34% hit rate)
    2: 250,  # Wow this file could be suspicious (35-44% hit rate)
    3: 500,  # Definitely Suspicious (45-50% hit rate)
    4: 750,  # Highly Suspicious, on the road to being malware (51-94% hit rate)
    5: 1000,  # Malware (95-100% hit rate)
}

# Default cap of 10k lines of stdout from tools, usually only applied to MalwareJail
STDOUT_LIMIT = 10000

# Strings indicative of a PE
PE_INDICATORS = [b"MZ", b"This program cannot be run in DOS mode"]

# Strings related to Character Data delimiters in markup languages
CDATA_START = "<![CDATA["
CDATA_END = "]]>"

# Variations of PowerShell found in WScript Shell commands
POWERSHELL_VARIATIONS = ["pwsh", "powershell"]

# Variations of Command Prompt found in WScript Shell commands
COMMAND_VARIATIONS = ["cmd"]

# Variations of cURL found in WScript Shell commands
CURL_VARIATIONS = ["curl"]

# Variations of bitsadmin found in WScript Shell commands
BITSADMIN_VARIATIONS = ["bitsadmin"]

# WshShell is a protected term because it is used as a module class name in MalwareJail
WSHSHELL = "WshShell"

# HTMLScriptElement/HTMLIFrameElement-related constants that will be used for seeking output in MalwareJail
HTMLSCRIPTELEMENT = "HTMLScriptElement"
HTMLIFRAMEELEMENT = "HTMLIFrameElement"
HTMLELEMENT_SRC_SET_TO_URI = ".src was set to a URI:"

# These characters are cannot be included in a variable name
INVALID_VARNAME_CHARS = ["-", " ", ":", ",", ";"]

# Enumerations
OBFUSCATOR_IO = "obfuscator.io"
MALWARE_JAIL = "MalwareJail"
JS_X_RAY = "JS-X-Ray"
BOX_JS = "Box.js"
SYNCHRONY = "Synchrony"
EXITED_DUE_TO_STDOUT_LIMIT = "EXITED_DUE_TO_STDOUT_LIMIT"
TEMP_JS_FILENAME = "temp_javascript.js"
GOOTLOADERAUTOJSDECODER = "GootLoaderAutoJsDecode"

# Default value for the maximum number of times the gauntlet should be run
# This usually gets exceeded when a script writes randomly generated content to the DOM
MAXIMUM_GAUNTLET_RUNS = 30

# When looking at HTML files, these are common terms found in phishing files
PHISHING_TITLE_TERMS = [
    # Classic phishing terms for file names
    "payment",
    "statement",
    "invoice",
    "notice",
    "download",
    "transfer",
    # These file-type specific terms of suspicious because this is an HTML file!
    "\.xls",
    "\.doc",
    "\.ppt",
    "\.one",
    "\.pdf",
    "microsoft",
    "adobe",
    "excel",
    "word",
    "powerpoint",
    "onenote",
    "pdf",
    # https://github.com/CAPESandbox/community/blob/815e21980f4b234cf84e78749447f262af2beef9/modules/signatures/secure_login_phish.py
    "secure login",
    "google doc",
    "dropbox",
    "google drive",
    "outlook",
    # https://github.com/CAPESandbox/community/blob/d010d2c8a8343a37e176133edb26e901c2c8ced9/modules/signatures/suspicious_html.py
    "please wait",
    "redirecting",
    "remittence",
    "remittance",
    "voicemail",
    # Other
    "paypal",
    "instagram",
    "facebook",
    "secure",
    "security",
    "sign",
    "bank",
    "ether",
    "coin",
    "files",
    "challenge",
    "card",
    "remember",
    "forgot",
    "verify",
    "confirm",
]

# There is a signature called "phishing_terms" which is used for detecting terms commonly associated with phishing
# in the JavaScript code / emulation output
# These values will be used for this signature, as well as looking for "input" elements in the HTML that use these.
PHISHING_INPUTS = [
    "email",
    "account",
    "phone",
    "skype",
    "e-mail",
    "authentication",
    "login",
    "username",
    "usrn",
    "psrd",
    "pswd",
    "passwd",
    "identity",
    "card",
    "mail",
    "challenge",
]

# Regular Expressions

# Examples:
# WScript.Shell[99].Run(do the thing)
# Shell.Application[99].ShellExecute(do the thing)
WSCRIPT_SHELL_REGEX = r"(?:WScript\.Shell|Shell\.Application)\[\d+\]\.(?:Run|ShellExecute|Exec)\((.*)\)"

# Example:
# /*!
#  * jQuery JavaScript Library v1.5
JQUERY_VERSION_REGEX = r"\/\*\!\n \* jQuery JavaScript Library v([\d\.]+)\n"

# Example:
# /**
# * Maplace.js
# *
# * Copyright (c) 2013 Daniele Moraschi
# * Licensed under the MIT license
# * For all details and documentation:
# * http://maplacejs.com
# *
# * @version  0.2.7
MAPLACE_REGEX = r"\/\*\*\n\* Maplace\.js\n[\n\r*\sa-zA-Z0-9\(\):\/\.@]+?@version  ([\d\.]+)\n"

# Example:
# /*
# Copyright (c) 2011 Sencha Inc. - Author: Nicolas Garcia Belmonte (http://philogb.github.com/)
COMBO_REGEX = (
    r"\/\*\nCopyright \(c\) 2011 Sencha Inc\. \- Author: Nicolas Garcia Belmonte \(http:\/\/philogb\.github\.com\/\)"
)

# Example:
# //     Underscore.js 1.13.6
UNDERSCORE_REGEX = r"\/\/     Underscore.js ([\d\.]+)\n"

# Example:
# (function(){d3 = {version: "1.29.5"}; // semver
D3_REGEX = r"\(function\(\)\{d3 = \{version: \"(1.29.5)\"\}; \/\/ semver"

# Example:
# /**
#  * @license
#  * Lodash <https://lodash.com/>
#  * Copyright OpenJS Foundation and other contributors <https://openjsf.org/>
#  * Released under MIT license <https://lodash.com/license>
#  * Based on Underscore.js 1.8.3 <http://underscorejs.org/LICENSE>
#  * Copyright Jeremy Ashkenas, DocumentCloud and Investigative Reporters & Editors
#  */
# ;(function() {

#   /** Used as a safe reference for `undefined` in pre-ES5 environments. */
#   var undefined;

#   /** Used as the semantic version number. */
#   var VERSION = '4.17.21';
LODASH_REGEX = (
    r"\/\*\*\n \* @license\n \* Lodash <https:\/\/lodash\.com\/>[\n\s*\w<:\/.>,&;(){}`\-=+]+var VERSION = '([\d.]+)';"
)

# Example:
#
# /*
# * Licensed to the Apache Software Foundation (ASF) under one
# * or more contributor license agreements.  See the NOTICE file
# * distributed with this work for additional information
# * regarding copyright ownership.  The ASF licenses this file
# * to you under the Apache License, Version 2.0 (the
# * "License"); you may not use this file except in compliance
# * with the License.  You may obtain a copy of the License at
# *
# *   http://www.apache.org/licenses/LICENSE-2.0
# *
# * Unless required by applicable law or agreed to in writing,
# * software distributed under the License is distributed on an
# * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# * KIND, either express or implied.  See the License for the
# * specific language governing permissions and limitations
# * under the License.
# */
#
# (function (global, factory) {
#     typeof exports === 'object' && typeof module !== 'undefined' ? factory(exports) :
#     typeof define === 'function' && define.amd ? define(['exports'], factory) :
#     (global = typeof globalThis !== 'undefined' ? globalThis : global || self, factory(global.echarts = {}));
# }(this, (function (exports) { 'use strict';
CHARTVIEW_REGEX = (
    r"\s*\/\*[\s\S]+?\*\/\s*\(function\s+\(global,\s*factory\)\s*\{\s*typeof\s+exports\s*===\s*'object'"
    r"\s*&&\s*typeof\s*module\s*!==\s*'undefined'\s*\?\s*factory\(exports\)\s*:\s*typeof\s+define\s*==="
    r"\s*'function'\s*&&\s*define\.amd\s*\?\s*define\(\['exports'\],\s*factory\)\s*:\s*\(global\s*=\s*"
    r"typeof\s+globalThis\s*!==\s*'undefined'\s*\?\s*globalThis\s*:\s*global\s*\|\|\s*self,\s*factory"
    r"\(global\.echarts\s*=\s*\{\}\)\);\s*\}\(this,\s*\(function\s*\(exports\)\s*\{\s*'use\s+strict';"
)

# Example:
# ;(function() {
# "use strict";

# /**
#  * @license
#  * Copyright 2015 Google Inc. All Rights Reserved.
#  *
#  * Licensed under the Apache License, Version 2.0 (the "License");
#  * you may not use this file except in compliance with the License.
#  * You may obtain a copy of the License at
#  *
#  *      http://www.apache.org/licenses/LICENSE-2.0
#  *
#  * Unless required by applicable law or agreed to in writing, software
#  * distributed under the License is distributed on an "AS IS" BASIS,
#  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  * See the License for the specific language governing permissions and
#  * limitations under the License.
#  */

# /**
#  * A component handler interface using the revealing module design pattern.
MDL_REGEX = r";\(function\(\)\s*\{\s*\"use\sstrict\";\s*\/\*\*[\s\S]+?\*\/[\s\S]*\/\*\*\s*\*\s*A component handler interface using the revealing module design pattern\."

# Example:
# [2023-02-07T14:08:19.018Z] mailware-jail, a malware sandbox ver. 0.20\n
MALWARE_JAIL_TIME_STAMP = "\[([\dTZ:\-.]+)\] "

# Example:
# data:image/png;base64,iVBORw0KGgoAAAAN
APPENDCHILD_BASE64_REGEX = re.compile("data:(?:[^;]+;)+base64,([\s\S]*)")

# Example:
# const element99_jsjaws =
ELEMENT_INDEX_REGEX = re.compile(b"const element(\d+)\w*_jsjaws = ")

# Example:
# wscript_shell_object_env("test") = "Hello World!";
VBSCRIPT_ENV_SETTING_REGEX = (
    b"[^;]\((?P<property_name>[\w\s()'\"+\\\\]{2,1000})\)\s*=\s*(?P<property_value>[^>=;\.]+?[^>=;]+);"
)

# Example:
# Exception occurred in aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa: object blahblah:123
# badinputhere
# SyntaxError: Unexpected end of input
INVALID_END_OF_INPUT_REGEX = (
    b"Exception occurred in [a-zA-Z0-9]{64}: object .+:\d+\n(.+)\nSyntaxError: Unexpected end of input"
)

# Example:
# Exception occurred in aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa: object blahblah:123
# missingfunction()
# ReferenceError: missingfunction is not defined
REFERENCE_NOT_DEFINED_REGEX = (
    b"Exception occurred in [a-zA-Z0-9]{64}: object .+:\d+\\n.+\\n\^\\nReferenceError: (.+) is not defined"
)

# JScript conditional comments
# Inspired by https://github.com/HynekPetrak/malware-jail/blob/master/jailme.js#L310:L315

# Example:
# /*@cc_on
AT_CC_ON_REGEX = b"\/\*@cc_on\s*"

# Example:
# @*/
AT_REGEX = b"@\*\/"

# Example:
# /*@if (@_jscript_version >= 7)
AT_IF_REGEX = b"\/\*@if\s*\(@_jscript_version\s[>=<]=\s\d\)\s*"

# Example:
# @elif (@_jscript_version >= 7)
AT_ELIF_REGEX = b"@elif\s*\(@_jscript_version\s[>=<]=\s\d\)\s*"

# Example:
# @else
AT_ELSE_REGEX = b"@else\s*"

# Example:
# /*@end
AT_END_REGEX = b"\/\*@end\s*"

JSCRIPT_REGEXES = [AT_CC_ON_REGEX, AT_REGEX, AT_IF_REGEX, AT_ELIF_REGEX, AT_ELSE_REGEX, AT_END_REGEX]

# Time-waster method structure, commonly found in Gootloader

# Examples:
# function blah1(blah2, blah3, blah4, blah5) {
#   blah6=blah7;
#    while(blah6<(blah2*blah8)) {
#       blah6 = blah6 + blah7;
#   }
# }
# or
# function blah1(blah2, blah3, blah4) {
#   blah5=blah6;
#   blah7=blah8;
#    while(blah7<(blah2*(blah9))) {
#       blah7++;
#   }
# }
WHILE_TIME_WASTER_REGEX = b"function\s*\w{2,15}\s*\((?:\w{2,15}(?:,\s*)?){1,5}\)\s*{(?:\s*\w{2,15}\s*=\s*\w{2,15};)+\s*while\s*\(\w{2,15}\s*<\s*\(\w{2,15}\s*\*\s*\(?\w{2,15}\)?\)\)\s*{\s*(?:\w{2,15}\s*=\s*\w{2,15}\s*\+\s*\w{2,15}\s*|\w{2,15}\+\+);\s*}\s*}"

# Examples:
# function blah1() {
#   blah2(blah3);
#   blah4 = blah5;
#   while(blah6 = blah7) {
#       try{
#           blah8[blah9](blah9);
#       } catch(blah10){
#           blah8[1272242] = blah11;
#       }
#       blah9++
#   }
# }
# or
# function blah1() {
#   blah2(blah3);
#   blah4 = blah5;
#   while(blah6) {
#       try{
#           blah7=blah8[blah9](blah9);
#       } catch(blah10){
#           blah11=1272242;
#           blah8[blah11] = blah12;
#       }
#       blah9++
#   }
# }
# or
# function blah1(blah2, blah3, blah4, blah5) {
#   blah6(blah7);
#   blah8 = blah9;
#   while (blah10) {
#           blah11++;
#           blah11 = blah11;
#       try {
#           blah12 = (blah13[blah11](blah11));
#       } catch (blah14) {
#           blah15 = 1272242;
#           blah13[(blah15)] = blah16;
#       }
#   }
# }
WHILE_TRY_CATCH_TIME_WASTER_REGEX = b"function\s+\w{2,15}\((?:\w{2,15}(?:,\s*)?){0,5}\)\s*{\s*\w{2,15}\(\w{2,15}\);\s*\w{2,15}\s*=\s*\w{2,15};\s*while\s*\(\w{2,15}\s*(?:=\s*\w{2,15})?\)\s*{\s*(?:\w{2,15}\[\w{2,15}\]\s*=\s*\w{2,15};\s*|\w{2,15}\s*=\s*\w{2,15};\s*|\w{2,15}\+\+;\s*)*try\s*{\s*(?:\w{2,15}\s*=\s*)?\(?\w{2,15}\[\w{2,15}\]\(\w{2,15}\)\)?;\s*}\s*catch\s*\(\w{2,15}\)\s*{\s*(?:\w{2,15}\[\(?\w{2,15}\)?\]\s*=\s*\w{2,15};|\w{2,15}\s*=\s*\w{2,15};\s*)+\s*}\s*(?:\w{2,15}\+\+;?)?\s*}\s*}"

TIME_WASTER_REGEXES = [WHILE_TIME_WASTER_REGEX, WHILE_TRY_CATCH_TIME_WASTER_REGEX]

# These regular are used for converting simple VBScript to JavaScript so that we can run it all in JsJaws

# Example:
# blah = "blahblah"
VBS_GRAB_VARS_REGEX = "(?P<variable_name>\w{2,10})\s*=\s*(?P<variable_value>[\"'].+[\"'])"

# Examples:
# Dim WshShell : Set WshShell = CreateObject("WScript.Shell")
# or
# Dim blah
# Set blah = CreateObject("wscript.shell")
VBS_WSCRIPT_SHELL_REGEX = (
    "Dim\s+(?P<varname>\w+)\s+:?\s*Set\s+(?P=varname)\s*=\s*CreateObject\([\"']wscript\.shell[\"']\)"
)

# Example:
# WshShell.RegWrite "blah\blah\blah\blah\blah", varname, "REG_SZ"
VBS_WSCRIPT_REG_WRITE_REGEX = (
    "%s\.RegWrite\s+(?P<key>[\w\"'\\\\]+),\s*(?P<content>[\w\"'.()]+),\s*(?P<type>[\w\"'.()]+)"
)

# Examples:
# blah "http://blah.com/evil.exe"
# or
# Call blah(varname)
VBS_FUNCTION_CALL = "(?:Call\s*)?%s\(?\s*(?P<func_args>[\w'\":\/.-]+)\s*\)?"

# Examples:
# var blah = Function("blah", varname);
# or
# var blah = new Function("blah", varnamey);
# or
# function blah(thing1, thing2)
# {
# 	return(new Function(thing1, thing2));
# }
JS_NEW_FUNCTION_REGEX = "(?:(var|function))\s+(?P<function_varname>\w+)(?:(\s*=\s*|\((?:\w{2,10}(?:,\s*)?)+\)\s*{\s*return\s*\())(?:new)?\s+Function\((?P<function_name>[\w\"']+),\s*(?P<args>[\w.()\"'\/&,\s]+)\)\)?;(\s*})?"

# Example:
# var new_blah = blah("blah", thing2);
JS_NEW_FUNCTION_REASSIGN_REGEX = "(?P<new_name>\w+)\s*=\s*%s"

# Example:
# document.write(unescape("blah"))
DOM_WRITE_UNESCAPE_REGEX = "(document\.write\(unescape\(.+\))"

# Example:
# document.write(atob(val));
DOM_WRITE_ATOB_REGEX = "(document\.write\((window\.)?atob\(.+\))"

# Example:
# HTMLScriptElement[9].src was set to a URI 'http://blah.com'
HTMLELEMENT_SRC_REGEX = f"(?:{HTMLSCRIPTELEMENT}|{HTMLIFRAMEELEMENT})\[[0-9]+\]{HTMLELEMENT_SRC_SET_TO_URI} '(.+)'"

# Example:
# <!-- HTML Encryption provided by www.blah.com -->
FULL_HTML_COMMENT_IN_JS = b"(^|\n)\s*(\<\!\-\-[\s\S]+?\-\-\>)\s*;?\n"

# Example:
# function a0nnnnoo() {
#     var fmicaiaimxeof = ['bunch', 'of', 'nonsense'];
#     a0nnnnoo = function() {
#         return fmicaiaimxeof;
#     };
#     return a0nnnnoo();
# };
FUNCTION_INCEPTION = b"function\s+(?P<function_name>\w+)\(\)\s*\{\s*var\s+(?P<variable_name>\w+)\s*=\s*\[[\s\S]+?\];\s*(?P=function_name)\s*=\s*function\(\)\s*\{\s*return\s+(?P=variable_name);\s*\};\s*return\s+(?P=function_name)\(\);\s*\};"

# Example:
# adc4bc7c-8f35-4a85-91e9-dc822b07f60d
BOX_JS_PAYLOAD_FILE_NAME = "[a-z0-9]{8}\-(?:[a-z0-9]{4}\-){3}[a-z0-9]{12}"

# Example:
# 'adc4bc7c-8f35-4a85-91e9-dc822b07f60d.js'
SNIPPET_FILE_NAME = BOX_JS_PAYLOAD_FILE_NAME + "\.js"

# Examples:
# <!DOCTYPE html>
# or
# <html>
HTML_START = b"(^|\n|\>)[ \t]*(?P<html_start><!doctype html>|<html)"

# Example:
# atob was seen decoding a URI: 'http://blah.com'
ATOB_URI_REGEX = "atob was seen decoding a URI: '(.+)'"

# Example:
# Payment.xls
# or
# Invoice.pdf
PHISHING_TITLE_TERMS_REGEX = r"\b(" + "|".join(PHISHING_TITLE_TERMS) + r")\b"


def is_vb_script(script: Tag) -> bool:
    return script.get("language", "").lower() == "vbscript" or script.get("type", "").lower() == "text/vbscript"


def is_js_script(script: Tag) -> bool:
    """Checks if script is javascript or jscript"""
    if "type" in script:
        return script["type"].lower() in ("", "text/javascript", "text/jscript")
    if "language" in script:
        return script["language"].lower() in ("", "javascript", "jscript")
    return True  # default is text/javascript if there is no type/language


class JsJaws(ServiceBase):
    def __init__(self, config: Optional[Dict] = None) -> None:
        super(JsJaws, self).__init__(config)
        self.artifact_list: Optional[List[Dict[str, str]]] = None
        self.malware_jail_payload_extraction_dir: Optional[str] = None
        self.malware_jail_sandbox_env_dump: Optional[str] = None
        self.malware_jail_sandbox_env_dir: Optional[str] = None
        self.malware_jail_sandbox_env_dump_path: Optional[str] = None
        self.path_to_jailme_js: Optional[str] = None
        self.path_to_boxjs: Optional[str] = None
        self.path_to_boxjs_boilerplate: Optional[str] = None
        self.path_to_jsxray: Optional[str] = None
        self.path_to_synchrony: Optional[str] = None
        self.boxjs_urls_json_path: Optional[str] = None
        self.malware_jail_urls_json_path: Optional[str] = None
        self.wscript_only_config: Optional[str] = None
        self.extracted_wscript_batch: Optional[str] = None
        self.extracted_wscript_ps1: Optional[str] = None
        self.extracted_wscript_batch_path: Optional[str] = None
        self.extracted_wscript_ps1_path: Optional[str] = None
        self.boxjs_batch: Optional[str] = None
        self.boxjs_batch_path: Optional[str] = None
        self.boxjs_ps1: Optional[str] = None
        self.boxjs_ps1_path: Optional[str] = None
        self.malware_jail_output: Optional[str] = None
        self.malware_jail_output_path: Optional[str] = None
        self.boxjs_output_dir: Optional[str] = None
        self.boxjs_iocs: Optional[str] = None
        self.boxjs_resources: Optional[str] = None
        self.boxjs_analysis_log: Optional[str] = None
        self.boxjs_snippets: Optional[str] = None
        self.cleaned_with_synchrony: Optional[str] = None
        self.cleaned_with_synchrony_path: Optional[str] = None
        self.stdout_limit: Optional[int] = None
        self.identify = forge.get_identify(use_cache=environ.get("PRIVILEGED", "false").lower() == "true")
        self.safelist: Dict[str, Dict[str, List[str]]] = {}
        self.doc_write_hashes: Optional[Set[str]] = None
        self.gauntlet_runs: Optional[int] = None
        # Used for maintaining the sample type as manipulations occur in the service per execution
        self.sample_type: Optional[str] = None
        # Script sources that are NOT programatically created
        # (or at least, written to the DOM via code)
        self.initial_script_sources: Optional[Set[str]] = None
        # Script sources that ARE programatically created
        # (or at least, written to the DOM via code)
        self.subsequent_script_sources: Optional[Set[str]] = None
        self.script_with_source_and_no_body: Optional[bool] = None
        self.scripts: Set[str] = set()
        self.malformed_javascript: Optional[bool] = None
        self.function_inception: Optional[bool] = None
        self.ignore_stdout_limit: Optional[bool] = None
        # Flag that the sample was embedded within a third party library
        self.embedded_code_in_lib: Optional[str] = None
        # List of malicious domains detected from a gootloader sample
        self.gootloader_uris: Optional[List[str]] = None
        # Persistence data from a gootloader sample
        self.gootloader_persistence: Optional[Dict[str, str]] = None
        # Flag that the sample contains a single script that writes unescaped values to the DOM
        self.single_script_with_unescape: Optional[bool] = None
        # Flag that the sample contains multiple scripts that write unescaped values to the DOM
        self.multiple_scripts_with_unescape: Optional[bool] = None
        # Flag that the sample contains leading garbage
        self.leading_garbage: Optional[bool] = None
        # Flag that the split_reverse_join signature was raised
        self.split_reverse_join: Optional[bool] = None
        # Flag that the file is phishing
        self.is_phishing: Optional[bool] = None
        # Flag that the file sets long base64-encoded strings to weird attributes, like innerText or input:value
        self.weird_base64_value_set: Optional[bool] = None
        # List of marks to indicate if a base64-encoded URL was base64-decoded
        self.base64_encoded_urls: List[str] = []
        # URL is seen in the same execution as a "SaveToFile", "WritesExecutable" and "RunsShell"
        self.url_used_for_suspicious_exec: Optional[bool] = None
        # Used for heuristic 22
        self.low_body_elements: Optional[bool] = None
        # Used for heuristic 23
        self.html_document_write: Optional[bool] = None
        # Used for heuristic 24
        self.html_phishing_title: Set[str] = set()
        # Used for heuristic 25
        self.phishing_inputs: Set[str] = set()
        # Used for heuristic 26
        self.password_input_and_no_form_action: Optional[bool] = None
        # List of URLs found in suspicious forms, used for heuristic 27
        self.sus_form_actions: Set[str] = set()
        # Map of scripts found and their corresponding entropies
        self.script_entropies: Dict[str, Any] = dict()
        # The number of web bugs/beacons found in an HTML document
        self.num_of_web_bugs = 0
        # Used for heuristic 25, to show that a form exists and that there are a small amount of input elements
        self.short_form = False
        self.log.debug("JsJaws service initialized")

    def start(self) -> None:
        try:
            self.safelist = self.get_api_interface().get_safelist()
        except ServiceAPIError as e:
            self.log.warning(f"Couldn't retrieve safelist from service: {e}. Continuing without it..")
        if not self.safelist:
            with open(SAFELIST_PATH, "r") as f:
                self.safelist = yaml_safe_load(f)

        self.stdout_limit = self.config.get("total_stdout_limit", STDOUT_LIMIT)

    def _reset_execution_variables(self) -> None:
        """
        This method resets variables that are expected to return to their default values when a new sample is received.
        :return: None
        """
        # Reset per sample
        self.doc_write_hashes = set()
        self.embedded_code_in_lib = None
        self.gootloader_uris = list()
        self.gootloader_persistence = dict()
        self.single_script_with_unescape = False
        self.multiple_scripts_with_unescape = False
        self.gauntlet_runs = 0
        self.initial_script_sources = set()
        self.subsequent_script_sources = set()
        self.scripts = set()
        self.script_with_source_and_no_body = False
        self.malformed_javascript = False
        self.function_inception = False
        self.leading_garbage = False
        self.split_reverse_join = False
        self.is_phishing = False
        self.weird_base64_value_set = False
        self.url_used_for_suspicious_exec = False
        self.low_body_elements = False
        self.html_document_write = False
        self.password_input_and_no_form_action = False
        self.base64_encoded_urls = []
        self.html_phishing_title = set()
        self.phishing_inputs = set()
        self.sus_form_actions = set()
        self.script_entropies = dict()
        self.num_of_web_bugs = 0
        self.short_form = False

    def _reset_gauntlet_variables(self, request: ServiceRequest) -> None:
        """
        This method resets variables that are expected to return to their default values when a gauntlet run begins.
        :param request: The ServiceRequest object
        :return: None
        """
        # Reset per gauntlet run
        self.artifact_list = []
        request.result = Result()
        self.script_with_source_and_no_body = False

    def _handle_filtered_code(self, file_path: str, file_content: bytes) -> Tuple[str, bytes]:
        """
        This method handles filtering code from third-party libraries, or not!
        :param file_path: The path of the file
        :param file_content: The content of the file
        :return: A tuple of the file path and the file content
        """
        # Let's try using the Gootloader-decoder lib first
        gootloader_config = gootloader_run(
            file_path,
            unsafe_uris=True,
            # The only reason we pass these variables is so that task cleanup is done
            payload_path=path.join(self.working_directory, "DecodedJsPayload.js_"),
            stage2_path=path.join(self.working_directory, "GootLoader3Stage2.js_"),
            log=self.log.debug,
        )

        # If we have a hit
        if gootloader_config and gootloader_config.urls:
            for uri in gootloader_config.urls:
                stripped_uri = uri.strip()
                # URI should exist, URI should actually be a URI, or URI is actually a domain
                if not stripped_uri or (not is_url(stripped_uri.encode()) and not is_domain(stripped_uri.encode())):
                    continue

                self.gootloader_uris.append(stripped_uri)

            if self.gootloader_uris:
                self.log.debug(f"Extracted malicious URIs from a GOOTLOADER sample using {GOOTLOADERAUTOJSDECODER}")
                self.embedded_code_in_lib = f"Unknown. We used {GOOTLOADERAUTOJSDECODER} to decode."
                if gootloader_config.persistence:
                    self.gootloader_persistence = gootloader_config.persistence.__dict__
                if gootloader_config.code:
                    return gootloader_config.final_stage_path, gootloader_config.code.encode()

        # Looks like the Gootloader-decoder did not work (at least for extracting the malicious code from the common
        # library). Let's try to use the libraries we manually extracted.
        try:
            filtered_file_path, filtered_file_content, lib_path = self._extract_filtered_code(file_content)
            if filtered_file_path and filtered_file_content:
                self.log.debug(f"Extracted malicious code from a third-party library: {lib_path}")
                file_path = filtered_file_path
                file_content = filtered_file_content
                self.embedded_code_in_lib = lib_path
        except UnicodeDecodeError:
            pass

        return file_path, file_content

    def _remove_leading_garbage_from_html(
        self, request: ServiceRequest, file_path: str, file_content: bytes
    ) -> Tuple[str, bytes]:
        """
        This method removes garbage text from HTML files that have been mis-identified
        :param request: The ServiceRequest object
        :param file_path: The path of the file
        :param file_content: The content of the file
        :return: A tuple of the file path and the file content
        """
        if request.file_type not in ["code/html", "code/hta", "code/svg"]:
            # First check to see there is an obvious <html> tag somewhere
            html_start = re.search(HTML_START, file_content)
            html_comment = None
            if not html_start:
                # If no obvious <html> tag, check if there are HTML/XML comments
                html_comment = re.search(FULL_HTML_COMMENT_IN_JS, file_content)

            if html_start or html_comment:
                # Setup some defaults for leading garbage and the script we want
                garbage = b""
                script_we_want = b""

                if html_start:
                    idx = file_content.index(html_start.group("html_start"))
                    # If the index is 0, then there is no leading garbage
                    if idx > 0:
                        garbage = file_content[:idx]
                        script_we_want = file_content[idx:]
                elif html_comment and len(html_comment.regs) > 2:
                    start_idx, end_idx = html_comment.regs[2]
                    # If the index is 0, then there is no leading garbage
                    if start_idx > 0:
                        garbage = file_content[start_idx:end_idx]
                        script_we_want = file_content[:start_idx] + file_content[end_idx:]

                # If there is leading garbage, write to disk and identify
                if garbage != b"":
                    with tempfile.NamedTemporaryFile(dir=self.working_directory, delete=False, mode="wb") as t:
                        t.write(garbage)
                        garbage_path = t.name

                    garbage_info = self.identify.fileinfo(garbage_path, generate_hashes=False)

                    with tempfile.NamedTemporaryFile(dir=self.working_directory, delete=False, mode="wb") as t:
                        t.write(script_we_want)
                        script_we_want_path = t.name

                    script_we_want_info = self.identify.fileinfo(script_we_want_path, generate_hashes=False)
                else:
                    # Otherwise, return!
                    return file_path, file_content

                if garbage_info["type"] not in [
                    "code/javascript",
                    "code/html",
                    "code/hta",
                    "code/jscript",
                    "code/wsf",
                    "code/wsc",
                ] and script_we_want_info["type"] in ["code/html", "code/hta", "image/svg"]:
                    self.log.debug("Removed garbage from the file...")
                    self.sample_type = script_we_want_info["type"]
                    return script_we_want_path, script_we_want
                else:
                    # If there is more than one HTML comment, recursively remove
                    html_comment = re.search(FULL_HTML_COMMENT_IN_JS, script_we_want)
                    if html_comment:
                        try:
                            return self._remove_leading_garbage_from_html(request, script_we_want_path, script_we_want)
                        except RecursionError as e:
                            self.log.debug(f"Exiting _remove_leading_garbage_from_html due to '{e}'")

        return file_path, file_content

    def _handle_vbscript_env_variables(self, file_path: str, file_content: bytes) -> Tuple[str, bytes]:
        """
        This is a VBScript method of setting an environment variable:

        var wscript_shell_object = CreateObject("WScript.Shell")
        var wscript_shell_object_env = wscript_shell_object.Environment("USER")
        wscript_shell_object_env("test") = "Hello World!";

        The above code is also valid in JavaScript when we are not intercepting the
        WScript.Shell object. However, since we are doing so, the act of
        setting the environment variable using round brackets is not possible and will
        result in an "ReferenceError: Invalid left-hand side in assignment"
        error.

        Therefore we are going to hunt for instances of this, and replace
        it with an accurate JavaScript technique for setting variables.

        :param file_path: The path of the file
        :param file_content: The content of the file
        :return: A tuple of the file path and the file content
        """

        def log_and_replace(match) -> bytes:
            """
            This nested method looks for matches of the VBSCRIPT_ENV_SETTING_REGEX regular
            expression, logs the match for debugging purposes, then replaces it
            :param match: The regular expression match
            :return: The value to replace the match
            """
            if len(match.regs) != 3:
                return
            property_name = match.group("property_name").decode()

            # We only want the last property assigned \(.+\), despite the regex capturing consecutive \(.+\)+
            if ")(" in property_name:
                # Therefore split
                split_property_name = match.group(0).split(b")(")[-1]
                another_match = re.search(VBSCRIPT_ENV_SETTING_REGEX, b"test(" + split_property_name)
                if another_match:
                    property_name = another_match.group("property_name").decode()
                    property_value = another_match.group("property_value").decode()

            try:
                property_value = match.group("property_value").decode()
            except UnicodeDecodeError:
                return

            self.log.debug(f"Replaced VBScript Env variable: ({truncate(property_name)}) = {truncate(property_value)};")
            # Since we are looking for the character prior to this assignment, we need to add it again
            leading_char_index = match.regs[0][0]
            try:
                decoded_match_string = match.string.decode()
            except UnicodeDecodeError:
                return
            if leading_char_index > len(decoded_match_string):
                return
            leading_char = decoded_match_string[leading_char_index]
            return f"{leading_char}[{property_name}] = {property_value};".encode()

        new_content = re.sub(VBSCRIPT_ENV_SETTING_REGEX, log_and_replace, file_content)
        if new_content != file_content:
            with tempfile.NamedTemporaryFile(dir=self.working_directory, delete=False, mode="wb") as f:
                file_content = new_content
                f.write(file_content)
                file_path = f.name

        return file_path, file_content

    def execute(self, request: ServiceRequest) -> None:
        file_path = request.file_path
        file_content = request.file_contents
        self.sample_type = request.file_type

        # Initial setup per sample
        self._reset_execution_variables()
        self.ignore_stdout_limit = request.get_param("ignore_stdout_limit")

        # Handle UTF-16 Encoding with BOM
        if file_content[:2] in (b"\xFF\xFE", b"\xFE\xFF"):
            file_content = file_content.decode("utf-16").encode("utf-8")
            with tempfile.NamedTemporaryFile(dir=self.working_directory, delete=False, mode="wb") as f:
                f.write(file_content)
                file_path = f.name

        original_contents = file_content

        if self.sample_type in ["code/javascript", "code/jscript"]:
            file_path, file_content = self._handle_filtered_code(file_path, file_content)

        file_path, file_content_with_no_leading_garbage = self._remove_leading_garbage_from_html(
            request, file_path, file_content
        )

        if file_content_with_no_leading_garbage != file_content:
            file_content = file_content_with_no_leading_garbage
            self.leading_garbage = True

        # There are always false positive hits in embedded code for VBScript env variables, so let's avoid that
        if not self.embedded_code_in_lib:
            file_path, file_content = self._handle_vbscript_env_variables(file_path, file_content)

        # File constants
        self.malware_jail_payload_extraction_dir = path.join(self.working_directory, "payload/")
        self.malware_jail_sandbox_env_dump = "sandbox_dump.json"
        self.malware_jail_sandbox_env_dir = path.join(self.working_directory, "sandbox_env")
        self.malware_jail_sandbox_env_dump_path = path.join(
            self.malware_jail_sandbox_env_dir, self.malware_jail_sandbox_env_dump
        )
        root_dir = path.dirname(path.abspath(__file__))
        self.path_to_jailme_js = path.join(root_dir, "tools/malwarejail/jailme.js")
        self.path_to_boxjs = path.join(root_dir, "tools/node_modules/box-js/run.js")
        self.path_to_boxjs_boilerplate = path.join(root_dir, "tools/node_modules/box-js/boilerplate.js")
        self.path_to_jsxray = path.join(root_dir, "tools/js-x-ray-run.js")
        self.path_to_synchrony = path.join(root_dir, "tools/node_modules/.bin/synchrony")
        self.malware_jail_urls_json_path = path.join(self.malware_jail_payload_extraction_dir, "urls.json")
        self.wscript_only_config = path.join(root_dir, "tools/malwarejail/config/config_wscript_only.json")
        self.extracted_wscript_batch = "extracted_wscript.bat"
        self.extracted_wscript_batch_path = path.join(
            self.malware_jail_payload_extraction_dir, self.extracted_wscript_batch
        )
        self.extracted_wscript_ps1 = "extracted_wscript.ps1"
        self.extracted_wscript_ps1_path = path.join(
            self.malware_jail_payload_extraction_dir, self.extracted_wscript_ps1
        )
        self.boxjs_batch = "boxjs_cmds.bat"
        self.boxjs_batch_path = path.join(self.malware_jail_payload_extraction_dir, self.boxjs_batch)
        self.boxjs_ps1 = "boxjs_cmds.ps1"
        self.boxjs_ps1_path = path.join(self.malware_jail_payload_extraction_dir, self.boxjs_ps1)
        self.malware_jail_output = "output.txt"
        self.malware_jail_output_path = path.join(self.working_directory, self.malware_jail_output)
        # Box.js creates an output directory in the working level directory with the name <file_name>.results
        # We must use globs to find the specific file paths
        self.boxjs_output_dir = path.join(self.working_directory, "*.results")
        self.boxjs_urls_json_path = path.join(self.boxjs_output_dir, "urls.json")
        self.boxjs_iocs = path.join(self.boxjs_output_dir, "IOC.json")
        self.boxjs_resources = path.join(self.boxjs_output_dir, "resources.json")
        self.boxjs_analysis_log = path.join(self.boxjs_output_dir, "analysis.log")
        self.boxjs_snippets = path.join(self.boxjs_output_dir, "snippets.json")
        self.cleaned_with_synchrony = f"{request.sha256}.cleaned"
        self.cleaned_with_synchrony_path = path.join(self.working_directory, self.cleaned_with_synchrony)

        # Setup directory structure
        if not path.exists(self.malware_jail_payload_extraction_dir):
            mkdir(self.malware_jail_payload_extraction_dir)

        if not path.exists(self.malware_jail_sandbox_env_dir):
            mkdir(self.malware_jail_sandbox_env_dir)

        self._run_the_gauntlet(request, file_path, file_content, original_contents)

        if path.exists(self.cleaned_with_synchrony_path):
            # Set this to avoid a loop of Synchrony extractions
            request.temp_submission_data["cleaned_by_synchrony"] = True

    def _raise_embedded_code_in_lib(self, request: ServiceRequest) -> None:
        """
        This method adds a section to the result that indicates that embedded code was found in a common library
        :param request: The ServiceRequest object
        :return: None
        """
        heur = Heuristic(4)
        embedded_code_in_lib_res_sec = ResultMultiSection(heur.name, heuristic=heur, parent=request.result)
        desc_body = TextSectionBody(heur.description)
        embedded_code_in_lib_res_sec.add_section_part(desc_body)
        lib_body = TextSectionBody(f"Common library used: {self.embedded_code_in_lib}")
        embedded_code_in_lib_res_sec.add_section_part(lib_body)
        if self.gootloader_persistence:
            title_body = TextSectionBody("Persistence data:")
            embedded_code_in_lib_res_sec.add_section_part(title_body)
            kv_body = KVSectionBody(**self.gootloader_persistence)
            embedded_code_in_lib_res_sec.add_section_part(kv_body)
            embedded_code_in_lib_res_sec.add_tag("file.name.extracted", self.gootloader_persistence.get("js_file_name"))
            embedded_code_in_lib_res_sec.add_tag(
                "file.name.extracted", self.gootloader_persistence.get("original_file_name")
            )
        embedded_code_in_lib_res_sec.add_tag("attribution.implant", "GOOTLOADER")
        embedded_code_in_lib_res_sec.add_tag("attribution.family", "GOOTLOADER")
        _ = add_tag(embedded_code_in_lib_res_sec, "network.dynamic.uri", self.gootloader_uris)
        _ = add_tag(embedded_code_in_lib_res_sec, "network.dynamic.domain", self.gootloader_uris)
        _ = add_tag(embedded_code_in_lib_res_sec, "network.dynamic.ip", self.gootloader_uris)
        if self.gootloader_uris:
            ioc_body = TextSectionBody()
            ioc_body.add_line("Gootloader IOCs:")
            for uri in self.gootloader_uris:
                ioc_body.add_line(f"\t-\t{safe_str(uri)}")
            embedded_code_in_lib_res_sec.add_section_part(ioc_body)

    def _strip_null_bytes(self, file_path: str, file_content: bytes) -> Tuple[str, bytes]:
        """
        If the file starts or ends with null bytes, let's strip them out
        :param file_path: The path of the file
        :param file_content: The content of the file
        :return: A tuple of the file path and the file content
        """
        if file_content.startswith(b"\x00") or file_content.endswith(b"\x00"):
            with tempfile.NamedTemporaryFile(dir=self.working_directory, delete=False, mode="wb") as f:
                file_content = file_content[:].strip(b"\x00")
                f.write(file_content)
                file_path = f.name
        return file_path, file_content

    def _is_time_waster(self, file_content: bytes, request: ServiceRequest) -> bool:
        """
        If the method uses a common time-waster structure, set tool timeout to a small number
        :param file_content: The content of the file
        :param request: The ServiceRequest object
        :return: A flag indicating if the file is a time waster or not
        """
        is_time_waster = False

        if self.embedded_code_in_lib:
            # This is a gootloader staple, so let's just set it here
            is_time_waster = True

        if not is_time_waster:
            for time_waster_regex in TIME_WASTER_REGEXES:
                time_waster_match = re.search(time_waster_regex, file_content)
                if time_waster_match:
                    break

        if is_time_waster:
            self.log.debug("This sample uses common time-wasting techniques")
            time_waster_res_sec = ResultTextSection("This sample uses common time-wasting techniques")
            time_waster_res_sec.set_heuristic(11)
            request.result.add_section(time_waster_res_sec)

        return is_time_waster

    def _setup_boxjs_args(self, request: ServiceRequest, tool_timeout: int) -> List[str]:
        """
        This method sets up the Box.js arguments which will be used to run the tool
        :param request: The ServiceRequest object
        :param tool_timeout: The time that the tool with run for
        :return: A list of arguments used for running Box.js
        """
        # --no-kill              Do not kill the application when runtime errors occur
        # --no-rewrite           Do not rewrite the source code at all, other than for `@cc_on` support
        # --loglevel             Logging level (debug, verbose, info, warning, error - default "info")
        # --output-dir           The location on disk to write the results files and folders to (defaults to the
        #                        current directory)
        # --timeout              The script will timeout after this many seconds (default 10)
        # --prepended-code       Prepend the JavaScript in the given file to the sample prior to sandboxing
        boxjs_args = [
            self.path_to_boxjs,
            "--no-kill",
            "--no-rewrite",
            "--loglevel=debug",
            f"--output-dir={self.working_directory}",
            f"--timeout={tool_timeout}",
            f"--prepended-code={self.path_to_boxjs_boilerplate}",
        ]

        no_shell_error = request.get_param("no_shell_error")
        # --no-shell-error       Do not throw a fake error when executing `WScriptShell.Run` (it throws a fake
        #                        error by default to pretend that the distribution sites are down, so that the
        #                        script will attempt to poll every site)
        if no_shell_error:
            boxjs_args.append("--no-shell-error")

        return boxjs_args

    def _setup_malware_jail_args(
        self, request: ServiceRequest, tool_timeout: int, css_path: Optional[str]
    ) -> List[str]:
        """
        This method sets up the Malware Jail arguments which will be used to run the tool
        :param request: The ServiceRequest object
        :param tool_timeout: The time that the tool with run for
        :param css_path: The path to the parsed stylesheet
        :return: A list of arguments used for running Malware Jail
        """
        browser_selected = request.get_param("browser")
        log_errors = request.get_param("log_errors")
        wscript_only = request.get_param("wscript_only")
        extract_function_calls = request.get_param("extract_function_calls")
        extract_eval_calls = request.get_param("extract_eval_calls")
        override_eval = request.get_param("override_eval")
        file_always_exists = request.get_param("file_always_exists")

        # -s odir  ... output directory for generated files (malware payload)
        # -o ofile ... name of the file where sandbox shall be dumped at the end
        # -b id    ... browser type, use -b list for possible values (Possible -b values:
        # [ 'IE11_W10', 'IE8', 'IE7', 'iPhone', 'Firefox', 'Chrome' ])
        # -t msecs - limits execution time by "msecs" milliseconds, by default 60 seconds.
        # -f filename ... the value of the script full name property to be set
        malware_jail_args = [
            "node",
            self.path_to_jailme_js,
            "-s",
            self.malware_jail_payload_extraction_dir,
            "-o",
            self.malware_jail_sandbox_env_dump_path,
            "-b",
            browser_selected,
            "-t",
            f"{tool_timeout * 1000}",
        ]

        # Pass the file name to MalwareJail
        filename = path.basename(request.task.file_name)
        malware_jail_args.extend(["-f", filename])

        # If a CSS file path was extracted from the HTML/HTA, pass it to MalwareJail
        if css_path:
            malware_jail_args.append(f"--stylesheet={css_path}")

        # Files that each represent a Function Call can be noisy and not particularly useful
        # This flag turns on this extraction
        if request.deep_scan or extract_function_calls:
            malware_jail_args.append("--extractfns")

        # Files that each represent a Eval Call can be noisy and not particularly useful
        # This flag turns on this extraction
        if request.deep_scan or extract_eval_calls:
            # If we want to extract eval calls, we need to use this sandbox sequence
            if not override_eval:
                malware_jail_args.extend(["-e", "sandbox_sequence_with_eval"])

            malware_jail_args.append("--extractevals")

        # By default, detonation takes place within a sandboxed browser. This option allows
        # for the sample to be run in WScript only
        if wscript_only:
            malware_jail_args.extend(["-c", self.wscript_only_config])

        # By default, we don't want to replace exception catching in a script with a log of the exception,
        # but it is useful for debugging
        if log_errors:
            malware_jail_args.append("--logerrors")

        # If we want to override the eval method to facilitate error logging and safe function execution, but to also
        # use indirect eval execution, use the following sandbox sequence
        if override_eval:
            malware_jail_args.extend(["-e", "sandbox_sequence_with_eval"])

        if file_always_exists:
            malware_jail_args.append("--filealwaysexists")

        return malware_jail_args

    def _setup_tool_args(
        self, request: ServiceRequest, tool_timeout: int, css_path: Optional[str]
    ) -> Tuple[List[str], List[str], List[str], List[str]]:
        """
        This method sets up the tool arguments which will be used to run tools
        :param request: The ServiceRequest object
        :param tool_timeout: The time that the tool with run for
        :param css_path: The path to the parsed stylesheet
        :return: A tuple consisting of lists of arguments used for several tools
        """
        # Grabbing service level configuration variables and submission variables
        download_payload = request.get_param("download_payload")
        allow_download_from_internet = self.config.get("allow_download_from_internet", False)
        throw_http_exc = request.get_param("throw_http_exc")

        boxjs_args = self._setup_boxjs_args(request, tool_timeout)

        malware_jail_args = self._setup_malware_jail_args(request, tool_timeout, css_path)

        jsxray_args = ["node", self.path_to_jsxray, f"{DIVIDING_COMMENT}\n"]

        synchrony_args = [self.path_to_synchrony, "deobfuscate", "--output", self.cleaned_with_synchrony_path]

        # If the Assemblyline environment is allowing service containers to reach the Internet,
        # then allow_download_from_internet service variable needs to be set to true

        # If the user has requested the sample to download any payload from the Internet, and
        # the service is allowed to reach the Internet, then add the following flag
        if allow_download_from_internet and download_payload:
            # --down   ... allow downloading malware payloads from remote servers
            malware_jail_args.append("--down=y")
            # --download             Actually download the payloads
            boxjs_args.append("--download")
        # If the user has requested the sample to download any payload from the Internet, and
        # the service is NOT allowed to reach the Internet, then add a ResultSection letting
        # them know and simulate all network call responses with a 404 Not Found
        elif not allow_download_from_internet and download_payload:
            request.result.add_section(ResultSection("Internet Access is disabled."))
            # --h404   ... on download return always HTTP/404
            malware_jail_args.append("--h404")
        # By selecting the throw_http_exc flag, the sandbox will throw an error in every
        # network call. This is useful for attempting different code execution paths.
        elif throw_http_exc:
            malware_jail_args.append("--t404")
        # As a default, the sandbox will simulate all network call responses with a 404 Not Found
        else:
            # Fake the download otherwise
            pass

        return boxjs_args, malware_jail_args, jsxray_args, synchrony_args

    @staticmethod
    def _is_single_line(file_content: bytes) -> bool:
        """
        This method is used for determining if the file contents are a single line
        :param file_content: The content of the file
        :return: A flag indicating if the file content is a single line
        """
        one_liner_hit = False
        is_single_line = len(list(filter(lambda item: item != b"", file_content.split(b"\n")))) == 1

        # Arbitrary suspicous length of a file
        if is_single_line and len(file_content) > 5000:
            one_liner_hit = True

        return one_liner_hit

    @staticmethod
    def _trim_malware_jail_output(malware_jail_output: List[str]) -> List[str]:
        """
        Find the log line when the sample was executed in MalwareJail, and the lines after that are the
        output that we want.
        :param malware_jail_output: A list of strings that make up the stdout output from Malware Jail
        :return: A potentially modified list of strings that make up the stdout output from Malware Jail
        """
        start_idx = len(malware_jail_output)
        end_idx = 0
        for idx, line in enumerate(malware_jail_output):
            if "==> Executing malware file(s). =========================================" in line:
                start_idx = idx
                break
            elif idx > 1000:
                # There's no way MalwareJail would output 1000 lines before executing the malware, right?!
                break

        for idx, line in reversed(list(enumerate(malware_jail_output))):
            if "==> Cleaning up sandbox." in line:
                # We want to include the line above
                end_idx = idx + 1
                break
            elif idx > 1000:
                # There's no way MalwareJail would output 1000 lines after cleaning up the sandbox, right?!
                break

        if start_idx < len(malware_jail_output) - 1 and end_idx > 0:
            malware_jail_output = malware_jail_output[start_idx:end_idx]
        elif start_idx < len(malware_jail_output) - 1:
            malware_jail_output = malware_jail_output[start_idx:]

        return malware_jail_output

    def _handle_tool_stdout_limit(
        self, tool: str, tool_output: List[str], tool_args: List[str], responses: Dict[str, List[str]]
    ) -> List[str]:
        """
        This method handles if the tool exits early due to the stdout limit being surpassed
        :param tool: The enumerator used for the tool name
        :param tool_output: A list of strings that make up the stdout output from the tool
        :param tool_args: A list of arguments used for running the tool
        :param responses: A dictionary used to contain the stdout from a tool
        :return: A list of strings that make up the stdout output from the tool
        """
        if len(tool_output) > 2 and tool_output[-2] == EXITED_DUE_TO_STDOUT_LIMIT:
            responses[tool] = [EXITED_DUE_TO_STDOUT_LIMIT]
            tool_timeout = tool_output[-1] + 5

            if tool == MALWARE_JAIL:
                timeout_arg_index = tool_args.index("-t")
                tool_args[timeout_arg_index + 1] = f"{tool_timeout * 1000}"
            elif tool == BOX_JS:
                # Box.js requires some more time to shut down
                tool_timeout += 10
                timeout_arg_index = tool_args.index(
                    next((arg for arg in tool_args if arg.startswith("--timeout=")), None)
                )
                tool_args[timeout_arg_index] = f"--timeout={tool_timeout}"

            self.log.debug(f"Running {tool} again with a timeout of {tool_timeout}s")
            tool_thr = Thread(target=self._run_tool, args=(tool, tool_args, responses), daemon=True)
            tool_thr.start()
            tool_thr.join(timeout=tool_timeout)
            tool_output = responses.get(tool, [])

        return tool_output

    def _handle_boxjs_output(self, responses: Dict[str, List[str]], boxjs_args: List[str]) -> List[str]:
        """
        This method handles retrieving the Box.js output
        :param responses: A dictionary used to contain the stdout from a tool
        :param boxjs_args: A list of arguments used for running Box.js
        :return: The a list of strings that make up the analysis log from Box.js
        """
        temp_boxjs_output = responses.get(BOX_JS, [])
        if not self.ignore_stdout_limit:
            temp_boxjs_output = self._handle_tool_stdout_limit(BOX_JS, temp_boxjs_output, boxjs_args, responses)

        boxjs_output: List[str] = []
        if len(glob(self.boxjs_analysis_log)) > 0:
            boxjs_analysis_log = max(glob(self.boxjs_analysis_log), key=path.getctime)
            with open(boxjs_analysis_log, "r") as f:
                for line in f:
                    # This creates clutter!
                    if line.startswith("[verb] Code saved to"):
                        continue
                    else:
                        boxjs_output.append(line)

        return boxjs_output

    def _handle_malware_jail_output(self, responses: Dict[str, List[str]], malware_jail_args: List[str]) -> List[str]:
        """
        This method handles the Malware Jail output
        :param responses: A dictionary used to contain the stdout from a tool
        :param malware_jail_args: A list of arguments used for running Malware Jail
        :return: A list of strings that make up the stdout output from Malware Jail
        """
        malware_jail_output = responses.get(MALWARE_JAIL, [])
        if not self.ignore_stdout_limit:
            malware_jail_output = self._handle_tool_stdout_limit(
                MALWARE_JAIL, malware_jail_output, malware_jail_args, responses
            )
        malware_jail_output = self._trim_malware_jail_output(malware_jail_output)
        return malware_jail_output

    @staticmethod
    def _handle_jsxray_output(responses) -> Dict[str, Any]:
        """
        This method handles JS-X-Ray output
        :param responses: A dictionary used to contain the stdout from a tool
        :return: A dictionary that make up the output from JS-X-Ray
        """
        jsxray_output: Dict[str, Any] = {}
        try:
            if len(responses.get(JS_X_RAY, [])) > 0:
                jsxray_output = loads(responses[JS_X_RAY][0])
        except JSONDecodeError:
            pass
        return jsxray_output

    def _run_the_gauntlet(
        self, request, file_path, file_content, original_contents, subsequent_run: bool = False
    ) -> None:
        """
        Welcome to the gauntlet. This is the method that you call when you want a file to run through all of the JsJaws
        tools and signatures. Ideally you should only call this when you are running an "improved" or "superset"
        version of the initial sample, since it will overwrite all result sections and artifacts from previous gauntlet
        runs.
        :param request: The ServiceRequest object
        :param file_path: The path of the file to use as we traverse this iteration of the gauntlet
        :param file_content: The content of the file to use as we traverse this iteration of the gauntlet
        :param subsequent_run: A flag indicating if this is not the initial gauntlet run
        :return: None
        """
        # Each time that we run through the gauntlet, increment this count
        self.gauntlet_runs += 1

        if self.gauntlet_runs > self.config.get("max_gauntlet_runs", MAXIMUM_GAUNTLET_RUNS):
            self.log.debug("Maximum number of gauntlet runs exceeded. Exiting...")
            return

        # Initial setup per gauntlet run
        self._reset_gauntlet_variables(request)

        # If there is embedded code in a common library, handle accordingly
        if self.embedded_code_in_lib:
            self._raise_embedded_code_in_lib(request)

        # If there is leading garbage, raise it up!
        if self.leading_garbage:
            heur = Heuristic(21)
            _ = ResultTextSection(heur.name, heuristic=heur, parent=request.result, body=heur.description)

        # Determine the file type to be used for this gauntlet run
        if not subsequent_run:
            file_type = self.sample_type
            file_type_details = dict(mime=None)
        else:
            file_type_details = self.identify.fileinfo(file_path, generate_hashes=False)
            file_type = file_type_details["type"]

        # Based on the file type, send to the proper extraction method
        css_path = None
        if file_type in ["code/html", "code/hta", "code/wsf", "code/wsc", "image/svg"]:
            file_path, file_content, css_path = self.extract_using_soup(request, file_content)
        elif file_type == "code/jscript":
            file_path, file_content = self.extract_js_from_jscript(file_content)
        # This case is if the file is invalid HTML or something similar
        elif file_type == "text/plain" and file_type_details["mime"] == "text/html":
            file_path, file_content, css_path = self.extract_using_soup(request, file_content)

        # If at this point the file path is None, there is nothing to analyze and we can go home
        # Note: There may not be any JavaScript to execute, but if there is a suspicious form action, then we should
        # generate a result.
        if file_path is None and not self.sus_form_actions:
            self.log.debug("No JavaScript file to analyze...")
            return

        # If we are attempting to determine if there is any JavaScript that was not generated by JsJaws, and if so,
        # then we want to run that. If not, then get outta here!
        if f"{DIVIDING_COMMENT}\n".encode() in file_content:
            split_content = file_content.split(f"{DIVIDING_COMMENT}\n".encode())
            if len(split_content) == 2:
                _, script_we_did_not_generate = split_content
            # Looks like a file generated by JsJaws and attached as supplementary was resubmitted for analysis.
            # Therefore we have to massage the file contents
            elif len(split_content) > 2:
                _, script_we_did_not_generate = split_content[-2:]
            else:
                script_we_did_not_generate = file_content
            if script_we_did_not_generate == b"" and not self.sus_form_actions:
                self.log.debug("No JavaScript file to analyze...")
                return

        # If we did manage to extract embedded code from a common library, add the extracted file as an artifact
        if self.embedded_code_in_lib and not any(
            artifact["name"] == TEMP_JS_FILENAME for artifact in self.artifact_list
        ):
            artifact = {
                "name": TEMP_JS_FILENAME,
                "path": file_path,
                "description": "Extracted JavaScript",
                "to_be_extracted": False,
            }
            self.log.debug(f"Adding supplementary JavaScript: {TEMP_JS_FILENAME}")
            self.artifact_list.append(artifact)

        # If the file consists of a single script with an unescape call, this is worth reporting
        if self.single_script_with_unescape:
            heur = Heuristic(14)
            _ = ResultTextSection(heur.name, heuristic=heur, parent=request.result, body=heur.description)
        elif self.multiple_scripts_with_unescape:
            heur = Heuristic(20)
            _ = ResultTextSection(heur.name, heuristic=heur, parent=request.result, body=heur.description)

        # If the HTML file has visible text that is most likely JavaScript
        if self.malformed_javascript:
            heur = Heuristic(17)
            _ = ResultTextSection(heur.name, heuristic=heur, parent=request.result, body=heur.description)

        # If the file uses function inception, this is annoying to read and hopefully no one with good intentions
        # would write code like this
        function_inception_match = re.search(FUNCTION_INCEPTION, file_content)
        if function_inception_match:
            self.log.debug("This sample uses function inception")
            heur = Heuristic(19)
            _ = ResultTextSection(heur.name, heuristic=heur, parent=request.result, body=heur.description)
            self.function_inception = True

        if self.html_phishing_title:
            phishing_title_heur = Heuristic(24)
            phishing_title_sec = ResultTextSection(
                phishing_title_heur.name, heuristic=phishing_title_heur, parent=request.result
            )
            phishing_title_sec.add_line(phishing_title_heur.description)
            phishing_title_sec.add_lines([f"\t- {title}" for title in sorted(self.html_phishing_title)])

        if self.phishing_inputs:
            phishing_inputs_heur = Heuristic(25)
            phishing_inputs_sec = ResultTextSection(
                phishing_inputs_heur.name, heuristic=phishing_inputs_heur, parent=request.result
            )
            phishing_inputs_sec.add_line(phishing_inputs_heur.description)
            phishing_inputs_sec.add_lines([f"\t- {item}" for item in sorted(self.phishing_inputs)])
            if self.short_form:
                phishing_inputs_heur.add_signature_id("short_form", 500)
                self.is_phishing = True

        if self.num_of_web_bugs:
            web_bugs_sec = ResultTextSection("Web bugs found", parent=request.result)
            web_bugs_sec.add_lines([f"{self.num_of_web_bugs} web bug(s)/beacon(s) found in document"])

        if self.password_input_and_no_form_action:
            pass_and_no_action_heur = Heuristic(26)
            pass_and_no_action_sec = ResultTextSection(
                pass_and_no_action_heur.name, heuristic=pass_and_no_action_heur, parent=request.result
            )
            pass_and_no_action_sec.add_line(pass_and_no_action_heur.description)

        if self.sus_form_actions:
            sus_form_action_heur = Heuristic(27)
            sus_form_action_sec = ResultTextSection(
                sus_form_action_heur.name, heuristic=sus_form_action_heur, parent=request.result
            )
            sus_form_action_sec.add_line(sus_form_action_heur.description)
            for item in sorted(self.sus_form_actions):
                sus_form_action_sec.add_line(f"\t- {item}")
                _ = add_tag(sus_form_action_sec, "network.static.uri", item)

        if self.script_entropies:
            script_entropies_sec = ResultSection("Script Entropies", parent=request.result, auto_collapse=True)
            for value in self.script_entropies.values():
                sub_entropy_section = ResultGraphSection(f"Script: {value['preview']}", parent=script_entropies_sec)
                sub_entropy_section.set_colormap(
                    cmap_min=0, cmap_max=8, values=[round(x, 5) for x in value["entropy"][1]]
                )

        # We don't want files that have leading or trailing null bytes as this can affect execution
        file_path, file_content = self._strip_null_bytes(file_path, file_content)

        # Time is of the essence!
        if not self._is_time_waster(file_content, request):
            tool_timeout = int(request.get_param("tool_timeout"))
        else:
            # Arbitrary small tool timeout
            tool_timeout = 5

        # Let's get all of the arguments needs to run the tools
        boxjs_args, malware_jail_args, jsxray_args, synchrony_args = self._setup_tool_args(
            request, tool_timeout, css_path
        )

        # If there is a DIVIDING_COMMENT in the script to run, extract the actual script, send that to
        # Synchrony/Box.js and check if script is a long one-liner
        one_liner_hit = False
        actual_script = None
        if f"{DIVIDING_COMMENT}\n".encode() in file_content:
            sections_of_script = file_content.split(f"{DIVIDING_COMMENT}\n".encode())
            if len(sections_of_script) == 2:
                _, actual_script = sections_of_script
                # Don't forget the sample!
                malware_jail_args.append(file_path)
            elif len(sections_of_script) > 2:
                # This case occurs when users resubmit the temp_javascript.js file
                # (a supplementary file not meant for resubmission). An additional DIVIDING_COMMENT is added since
                # there is no context that the previous writes to the DOM were from a prior execution. We'll check here
                # if there is any duplication of script "sections" for dynamically created code.
                section_hashes = set()

                # MalwareJail requires the whole (non-duplicated) picture.
                script_for_malware_jail = b""
                file_for_malware_jail = None
                for section in sections_of_script:
                    section_hash = sha256(section).hexdigest()
                    if section_hash in section_hashes:
                        continue
                    else:
                        section_hashes.add(section_hash)
                        script_for_malware_jail, file_for_malware_jail = self.append_content(
                            section.decode(), script_for_malware_jail, file_for_malware_jail
                        )

                file_for_malware_jail.close()
                malware_jail_args.append(file_for_malware_jail.name)

                # There will be some duplication here in the file contents but that is fine since we are already
                # tracking the contents written to the DOM. This is for Synchrony, Box.js and JS-X-Ray.
                actual_script = sections_of_script[-1]
            else:
                return

            # Synchrony, Box.js and JS-X-Ray want the original script
            with tempfile.NamedTemporaryFile(dir=self.working_directory, delete=False, mode="wb") as t:
                t.write(actual_script)
                synchrony_args.append(t.name)
                # Box.js cannot handle the document object, therefore we need to pass it the split file
                boxjs_args.append(t.name)
                jsxray_args.append(t.name)

            one_liner_hit = self._is_single_line(actual_script)
        else:
            # Don't forget the sample!
            malware_jail_args.append(file_path)
            synchrony_args.append(file_path)
            boxjs_args.append(file_path)
            jsxray_args.append(file_path)

            one_liner_hit = self._is_single_line(file_content)

        if one_liner_hit:
            heur = Heuristic(10)
            _ = ResultTextSection(heur.name, heuristic=heur, parent=request.result, body=heur.description)

        if self.low_body_elements:
            low_body_heur = Heuristic(22)
            _ = ResultSection(
                low_body_heur.name, low_body_heur.description, heuristic=low_body_heur, parent=request.result
            )

        tool_threads: List[tuple[str, Thread]] = []
        responses: Dict[str, List[str]] = {}
        if not request.get_param("static_analysis_only"):
            tool_threads.append(
                (BOX_JS, Thread(target=self._run_tool, args=(BOX_JS, boxjs_args, responses), daemon=True))
            )
            tool_threads.append(
                (
                    MALWARE_JAIL,
                    Thread(target=self._run_tool, args=(MALWARE_JAIL, malware_jail_args, responses), daemon=True),
                )
            )
        tool_threads.append(
            (JS_X_RAY, Thread(target=self._run_tool, args=(JS_X_RAY, jsxray_args, responses), daemon=True))
        )

        # There are three ways that Synchrony will run.
        has_synchrony_run = False

        # 1. If it is enabled in the submission parameter
        if request.get_param("enable_synchrony"):
            tool_threads.append(
                (SYNCHRONY, Thread(target=self._run_tool, args=(SYNCHRONY, synchrony_args, responses), daemon=True))
            )
            has_synchrony_run = True
        else:
            for yara_rule in listdir("./yara"):
                rules = yara_compile(filepath=path.join("./yara", yara_rule))
                try:
                    matches = rules.match(file_path)
                except YARAError as e:
                    self.log.debug(f"Could not open file {file_path} due to '{e}'")
                    matches = []
                # 2. If the yara rule that looks for obfuscator.io obfuscation hits on the file
                if matches:
                    tool_threads.append(
                        (
                            SYNCHRONY,
                            Thread(target=self._run_tool, args=(SYNCHRONY, synchrony_args, responses), daemon=True),
                        )
                    )
                    has_synchrony_run = True
                    break

        for _, thr in tool_threads:
            thr.start()

        synchrony_timedout = False
        for name, thr in tool_threads:
            thr.join(timeout=tool_timeout)
            if thr.is_alive():
                if name == SYNCHRONY:
                    synchrony_timedout = True
                self.log.debug(f"{name} did not finish. Look at previous logs...")
                # Give the tool a chance to clean up after to the tool timeout
                sleep(3)

        # Handle each tools' output
        boxjs_output = self._handle_boxjs_output(responses, boxjs_args)
        malware_jail_output = self._handle_malware_jail_output(responses, malware_jail_args)
        jsxray_output = self._handle_jsxray_output(responses)

        # ==================================================================
        # Magic Section
        # ==================================================================

        # We are running signatures based on the output observed from dynamic execution
        # (boxjs_output and malware_jail_output)
        # as well as the file contents themselves (static analysis)
        if request.get_param("static_signatures"):
            static_file_lines = []
            for line in safe_str(file_content).split("\n"):
                if ";" in line:
                    static_file_lines.extend(line.split(";"))
                else:
                    static_file_lines.append(line)
            if not self.ignore_stdout_limit:
                total_output = (
                    boxjs_output[: self.stdout_limit] + malware_jail_output[: self.stdout_limit] + static_file_lines
                )
            else:
                total_output = boxjs_output + malware_jail_output + static_file_lines
        else:
            if not self.ignore_stdout_limit:
                total_output = boxjs_output[: self.stdout_limit] + malware_jail_output[: self.stdout_limit]
            else:
                total_output = boxjs_output + malware_jail_output

        if not self.ignore_stdout_limit:
            total_output = total_output[: self.stdout_limit]

        display_iocs = request.get_param("display_iocs")
        self._run_signatures(total_output, request.result, display_iocs)

        if self.html_document_write and self.sample_type == "code/html":
            doc_write_heur = Heuristic(23)
            _ = ResultSection(
                doc_write_heur.name, doc_write_heur.description, heuristic=doc_write_heur, parent=request.result
            )

        self._extract_boxjs_iocs(request.result)
        if not self.ignore_stdout_limit:
            self._extract_malware_jail_iocs(malware_jail_output[: self.stdout_limit], request, original_contents)
        else:
            self._extract_malware_jail_iocs(malware_jail_output, request, original_contents)

        self._handle_subsequent_scripts(request.result)
        self._extract_wscript(total_output, request.result)
        self._extract_payloads(request.sha256, request.deep_scan)
        self._extract_urls(request)

        if request.get_param("add_supplementary"):
            self._extract_supplementary(malware_jail_output)

        # 3. If JS-X-Ray has detected that the sample was obfuscated with obfuscator.io, then run Synchrony
        run_synchrony = self._flag_jsxray_iocs(jsxray_output, request)
        if not has_synchrony_run and run_synchrony:
            synchrony_thr = Thread(target=self._run_tool, args=(SYNCHRONY, synchrony_args, responses), daemon=True)
            synchrony_thr.start()
            synchrony_thr.join(timeout=tool_timeout)

        # TODO: Do something with the Synchrony output
        _ = responses.get(SYNCHRONY)

        self._extract_synchrony(request, synchrony_timedout)

        # This has to be the second last thing that we do, since it will run on a "superset" of the initial file...
        if not self.ignore_stdout_limit:
            self._extract_doc_writes(malware_jail_output[: self.stdout_limit], request, original_contents)
        else:
            self._extract_doc_writes(malware_jail_output, request, original_contents)

        # Adding sandbox artifacts using the OntologyResults helper class
        _ = OntologyResults.handle_artifacts(sorted(self.artifact_list, key=lambda x: x["name"]), request)

    def append_content(
        self, content: str, js_content: bytes, aggregated_js_script: Optional[tempfile.NamedTemporaryFile]
    ) -> Tuple[bytes, tempfile.NamedTemporaryFile]:
        """
        This method appends contents to a NamedTemporaryFile
        :param content: content to be appended
        :param js_content: The file content of the NamedTemporaryFile
        :param aggregated_js_script: The NamedTemporaryFile object
        :return: A tuple of the file contents of the NamedTemporaryFile object and the NamedTemporaryFile object
        """
        encoded_script = content.encode()
        if aggregated_js_script is None:
            aggregated_js_script = tempfile.NamedTemporaryFile(dir=self.working_directory, delete=False, mode="wb")
        js_content += encoded_script + b"\n"
        aggregated_js_script.write(encoded_script + b"\n")
        return js_content, aggregated_js_script

    def insert_content(
        self, content: str, js_content: bytes, aggregated_js_script: Optional[tempfile.NamedTemporaryFile]
    ) -> Tuple[bytes, tempfile.NamedTemporaryFile]:
        """
        This method inserts contents above the dividing comment line in a NamedTemporaryFile
        :param content: content to be inserted
        :param js_content: The file content of the NamedTemporaryFile
        :param aggregated_js_script: The NamedTemporaryFile object
        :return: A tuple of the file contents of the NamedTemporaryFile object and the NamedTemporaryFile object
        """
        encoded_script = content.encode()
        if aggregated_js_script is None:
            aggregated_js_script = tempfile.NamedTemporaryFile(dir=self.working_directory, delete=False, mode="wb")
        # Get the point in the file contents where the divider exists
        if js_content != b"":
            index_of_divider = js_content.index(DIVIDING_COMMENT.encode())
            # Find the beginning of the file
            aggregated_js_script.seek(0, 0)
            # Insert the encoded script before the divider
            js_content = js_content[:index_of_divider] + encoded_script + b"\n" + js_content[index_of_divider:]
            aggregated_js_script.write(js_content)
            # Find the end of the file
            aggregated_js_script.seek(0, 2)
        return js_content, aggregated_js_script

    def extract_using_soup(
        self,
        request: ServiceRequest,
        file_content: bytes,
        js_content: bytes = b"",
        aggregated_js_script: Optional[tempfile.NamedTemporaryFile] = None,
        insert_above_divider: bool = False,
    ) -> Tuple[Optional[str], bytes, Optional[str]]:
        """
        This method extracts elements from an HTML file using the BeautifulSoup library
        :param request: The ServiceRequest object
        :param file_content: The contents of the non-pure JavaScript file to be read
        :param js_content: The file content of the NamedTemporaryFile
        :param aggregated_js_script: The NamedTemporaryFile object
        :param insert_above_divider: A flag indicating if we are inserting above the divider
        :return: A tuple of the JavaScript file name that was written, the contents of the file that was written,
                 and the name of the CSS file that was written
        """
        self.log.debug("Extracting HTML elements from soup...")

        start_time = time()
        try:
            soup = BeautifulSoup(file_content, features="html5lib")
        except AssertionError:
            self.log.debug("Could not parse file contents with BeautifulSoup due to 'AssertionError'")
            return None, None, None

        self.log.debug(f"Parsing the file with BeautifulSoup took {round(time() - start_time)}s")

        js_script_name = None
        css_script_name = None

        aggregated_js_script, js_content = self._extract_js_using_soup(
            soup, aggregated_js_script, js_content, request, insert_above_divider
        )

        if self.sample_type in ["code/html", "code/hta"]:
            aggregated_js_script, js_content = self._extract_embeds_using_soup(
                soup, request, aggregated_js_script, js_content
            )
            css_script_name, aggregated_js_script, js_content = self._extract_css_using_soup(
                soup, request, aggregated_js_script, js_content
            )
            self._hunt_for_suspicious_titles(soup)
            self._hunt_for_suspicious_input_fields(soup)
            self._hunt_for_suspicious_forms(soup)
            self._hunt_for_suspicious_meta(soup, request)
            self._hunt_for_suspicious_images(soup)

        if aggregated_js_script:
            aggregated_js_script.close()
            artifact = {
                "name": TEMP_JS_FILENAME,
                "path": aggregated_js_script.name,
                "description": "Extracted JavaScript",
                "to_be_extracted": False,
            }
            self.log.debug(f"Adding extracted JavaScript: {TEMP_JS_FILENAME}")
            self.artifact_list.append(artifact)
            js_script_name = aggregated_js_script.name

        if js_content != b"":
            return js_script_name, js_content, css_script_name
        return js_script_name, file_content, css_script_name

    def extract_js_from_jscript(self, file_content: bytes) -> Tuple[str, bytes]:
        """
        This method extracts JavaScript from JScript
        :param file_content: The contents of the JScript file to be read
        :return: A tuple of the JavaScript file name that was written, the contents of the file that was written
        """

        def log_and_replace_jscript(match):
            group_0 = match.group(0).decode()
            self.log.debug(f"Removed JScript conditional comment: {group_0}")
            return b""

        for regex in JSCRIPT_REGEXES:
            file_content = re.sub(regex, log_and_replace_jscript, file_content)

        with tempfile.NamedTemporaryFile(dir=self.working_directory, delete=False, mode="wb") as f:
            f.write(file_content)

        return f.name, file_content

    def _extract_embeds_using_soup(
        self,
        soup: BeautifulSoup,
        request: ServiceRequest,
        aggregated_js_script: Optional[tempfile.NamedTemporaryFile],
        js_content: bytes = b"",
    ) -> Tuple[Optional[tempfile.NamedTemporaryFile], Optional[bytes]]:
        """
        This method extracts files from embed tag sources via BeautifulSoup enumeration
        :param soup: The BeautifulSoup object
        :param request: The ServiceRequest object
        :param aggregated_js_script: The NamedTemporaryFile object
        :param js_content: The file content of the NamedTemporaryFile
        :return: A tuple of the JavaScript file that was written and the contents of the file that was written
        """
        self.log.debug("Extracting embedded files from soup...")
        embed_srcs: Set[str] = set()

        # https://www.w3schools.com/tags/att_src.asp
        # Supported and inspired by https://github.com/sandialabs/laikaboss/blob/8dd2ca17c18d4d0d363d566798720acb7b4d3662/laikaboss/modules/scan_html.py#L60
        elements_with_src_attr = [
            "audio",
            "embed",
            "frame",
            "iframe",
            "img",
            "input",
            # Inspired by https://github.com/sandialabs/laikaboss/blob/8dd2ca17c18d4d0d363d566798720acb7b4d3662/laikaboss/modules/scan_html.py#L197
            "object",
            "script",
            "source",
            "track",
            "v:fill",
            "v:image",
            "v:oval",
            "v:rect",
            "v:roundrect",
            "video",
        ]

        # https://www.w3schools.com/tags/att_href.asp
        elements_with_href_attr = ["a", "area", "base", "link"]

        elements_with_attr_of_interest = elements_with_src_attr + elements_with_href_attr
        embeds = soup.findAll(elements_with_attr_of_interest)

        for embed in embeds:
            element_name = embed.name
            src = embed.attrs.get("src")
            if not src:
                src = embed.attrs.get("href")
                if not src:
                    continue

            matches = re.match(APPENDCHILD_BASE64_REGEX, src)
            if matches and len(matches.regs) == 2:
                try:
                    embedded_file_content = b64decode(matches.group(1).encode())
                except BinasciiError as e:
                    self.log.debug(
                        f"Could not base64-decode an element src/href value '{matches.group(1)}' due to '{e}'"
                    )
                    continue

                if embedded_file_content not in embed_srcs:
                    embed_srcs.add(embedded_file_content)
                else:
                    continue

                with tempfile.NamedTemporaryFile(dir=self.working_directory, delete=False, mode="wb") as t:
                    t.write(embedded_file_content)
                    embed_path = t.name

                # We also want to aggregate Javscript scripts, but prior to the DIVIDING_COMMENT break, if it exists
                file_info = self.identify.fileinfo(embed_path, generate_hashes=False)
                if file_info["type"] in ["code/html", "code/hta", "code/wsf", "code/wsc", "image/svg"]:
                    file_path, js_content, _ = self.extract_using_soup(
                        request, embedded_file_content, js_content, aggregated_js_script, insert_above_divider=True
                    )
                    if file_path:
                        aggregated_js_script = open(file_path, "a+b")
                elif file_info["type"] in ["code/javascript"]:
                    js_content, aggregated_js_script = self.append_content(
                        embedded_file_content.decode(), js_content, aggregated_js_script
                    )
                else:
                    artifact = {
                        "name": get_sha256_for_file(embed_path),
                        "path": embed_path,
                        "description": f"Base64-decoded {element_name} Tag Source",
                        "to_be_extracted": True,
                    }
                    self.log.debug(f"Extracting decoded {element_name} tag source {embed_path}")
                    self.artifact_list.append(artifact)

        return aggregated_js_script, js_content

    def _search_script_contents_for_unescapes(self, script_contents_list: List[str]) -> bool:
        """
        This method searches a list of script contents (usually with length of 1) using regular expressions,
        hunting for simple obfuscation
        :param script_contents_list: The contents of a Soup script, in list format
        :return: Do the script contents contain simple obfuscation?
        """

        script_contents = script_contents_list[0] if script_contents_list else ""
        for regex in [DOM_WRITE_UNESCAPE_REGEX, DOM_WRITE_ATOB_REGEX]:
            # An unescaped value of decent length is written to the DOM
            if len(script_contents) > 250 and re.search(regex, script_contents, re.IGNORECASE):
                self.log.debug(f"Script was found that used {regex}...")
                # There is a high chance that enforcing the stdout limit when there is
                # a single script that uses an unescape could prevent us from
                # correctly executing this sample, therefore ignore this limit
                self.ignore_stdout_limit = True
                return True
        return False

    def _contains_scripts_with_unescape(self, soup: BeautifulSoup, scripts: ResultSet[Tag]) -> None:
        """
        This method checks if the file content is contains scripts that are made up of
        large "unescape" calls
        :param soup: The BeautifulSoup object
        :param scripts: A list of Script soup elements
        :return: None
        """
        soup_body_contents = []
        if soup.body:
            soup_body_contents = soup.body.contents

        # If the soup consists of a single script element, let's dive in a little
        # deeper to see if this file is suspicious
        if not self.single_script_with_unescape and soup_body_contents == [] and len(scripts) == 1:
            script_contents_list = scripts[0].contents
            self.single_script_with_unescape = self._search_script_contents_for_unescapes(script_contents_list)

        # If the soup contains multiple script elements, and more than one contains simple obfuscation, flag it!
        elif not self.single_script_with_unescape and len(scripts) > 1:
            count = 0
            for script in scripts:
                script_contents_list = script.contents
                script_contains_unescape = self._search_script_contents_for_unescapes(script_contents_list)
                if script_contains_unescape:
                    count += 1

            if count > 1:
                self.multiple_scripts_with_unescape = True

    def _skip_element(self, element: Tag) -> bool:
        """
        This method is used for determining if we should dynamically create an element
        :param element: The BeautifulSoup element
        :return: A flag indicating if we should skip creating the element
        """
        # We don't want these elements dynamically created
        if element.name in ["head", "style", "body", "param"]:
            return True

        # If the file is code/wsf, skip the job and package elements
        elif element.name in ["job", "package"] and self.sample_type == "code/wsf":
            return True

        # If the file is code/wsc, skip the component element
        elif element.name in ["component"] and self.sample_type == "code/wsc":
            return True

        # If there is a script element that just points at a src, we want it!
        elif element.name in ["script"] and element.string is not None and element.string.strip():
            return True

        elif self._skip_embed_element(element):
            return True

        # If we have a meta element that does not have http-equiv set to refresh and content attributes, skip it
        elif element.name in ["meta"] and not (
            element.attrs.get("http-equiv")
            and element.attrs.get("http-equiv").lower() == "refresh"
            and element.attrs.get("content")
        ):
            return True

        return False

    def _remove_safelisted_element_attrs(self, element: Tag) -> Tag:
        """
        If an element has an attribute that is safelisted, don't include it when we create the element
        :param element: The BeautifulSoup element
        :return: A potentially modified BeautifulSoup element
        """
        if element.name in SAFELISTED_ATTRS_TO_POP:
            for attr in SAFELISTED_ATTRS_TO_POP[element.name]:
                if is_tag_safelisted(
                    element.attrs.get(attr, ""), ["network.static.domain", "network.static.uri"], self.safelist
                ):
                    element.attrs.pop(attr)
        return element

    @staticmethod
    def _skip_embed_element(element: Tag) -> bool:
        """
        This method is used for determining if we should dynamically create an embedded element which
        could be created elsewhere
        :param element: The BeautifulSoup element
        :return: A flag indicating if we should skip creating the element
        """
        # To avoid duplicate of embed extraction, check if embed matches criteria used in
        # the extract_embeds_using_soup method
        if element.name == "embed":
            src = element.attrs.get("src")
            if src and re.match(APPENDCHILD_BASE64_REGEX, src):
                return True
        return False

    @staticmethod
    def _determine_last_index(index: int, insert_above_divider: bool, js_content: bytes) -> int:
        """
        If we are inserting an element above the divider, we should grab the last index used and add to that...
        Find last occurrence of "element{}_jsjaws ="" in the js_content
        :param index: The index of the element in the list of all elements
        :param insert_above_divider: A flag indicating if we are inserting above the divider
        :param js_content: The file content of the NamedTemporaryFile
        :return: The last index used
        """
        if insert_above_divider:
            matches = re.findall(ELEMENT_INDEX_REGEX, js_content)
            last_used_index = int(matches[-1])
            idx = index + last_used_index + 1
        else:
            idx = index

        return idx

    @staticmethod
    def create_unique_element_id(element_id: str, set_of_variable_names: Set[str]) -> str:
        """
        If the proposed element ID already exists, then mock one
        :param element_id: The element id
        :param set_of_variable_names: A set containing all variable names
        :return: The name of the element ID
        """
        if element_id in set_of_variable_names:
            proposed_element_id = element_id
            while element_id in set_of_variable_names:
                element_id = f"{proposed_element_id}{get_id_from_data(element_id)}"
        return element_id

    @staticmethod
    def _determine_element_id(element: Tag, idx: int, set_of_variable_names: Set[str]) -> str:
        """
        This method determines the element id of the element, and will create one if
        the "id" field is not set
        :param element: The BeautifulSoup element
        :param idx: The last index used
        :param set_of_variable_names: A set containing all variable names
        :return: The element id
        """
        # If the element does not have an ID, mock one
        element_id = element.attrs.get("id", f"element{idx}")

        # If the element id attribute is specifically set to an empty string, mock the varname
        if element_id == "":
            element_id = f"element{idx}"

        element_id = JsJaws.create_unique_element_id(element_id, set_of_variable_names)

        return element_id

    @staticmethod
    def _determine_element_varname(element: Tag, element_id: str, set_of_variable_names: Set[str]) -> str:
        """
        This method determines the name of the variable representing the element
        :param element: The BeautifulSoup element
        :param element_id: The element id
        :param set_of_variable_names: A set containing all variable names
        :return: The name of the variable
        """
        # <object> tags are special https://developer.mozilla.org/en-US/docs/Web/HTML/Element/object
        if element.name == "object":
            # We cannot assign a random element variable name to object tag elements
            random_element_varname = element_id
        else:
            # JavaScript variables cannot have hyphens, spaces, colons, commas, semi-colons, etc. in their names
            for invalid_varname_char in INVALID_VARNAME_CHARS:
                if invalid_varname_char in element_id:
                    element_id = element_id.replace(invalid_varname_char, "_")

            # Let's be reasonable with variable name length
            if len(element_id) > 25:
                element_id = element_id[:25]

            element_id = JsJaws.create_unique_element_id(element_id, set_of_variable_names)
            set_of_variable_names.add(element_id)
            random_element_varname = f"{element_id.lower()}_jsjaws"

            # If the random_element_varname starts with a number, prepend that with a string
            if random_element_varname[0].isdigit():
                random_element_varname = "jsjaws_" + random_element_varname
        return random_element_varname

    def _determine_element_value(self, element: Tag) -> str:
        """
        This method determines the value of an element
        :param element: The BeautifulSoup element
        :return: The element value
        """
        # We cannot trust the text value of these elements, since it contains all nested items within it...
        if element.name in ["div", "p", "svg"]:
            try:
                element_string = element.string
            except RecursionError as e:
                self.log.debug(f"Could not access the element.string value due to '{e}'")
                element_string = element.text if hasattr(element, "text") else ""
            # If the element contains a script child, and the element's string is the same as the script child's,
            # set value to None
            if element.next and element.next.name == "script" and element_string == element.next.string:
                element_value = None
            elif element_string is not None:
                element_value = element_string.strip().replace("\n", "")
            else:
                element_value = None
        else:
            if hasattr(element, "text"):
                element_value = element.text.strip().replace("\n", "")
            else:
                element_value = ""

        return element_value

    @staticmethod
    def _initialize_create_element_script(random_element_varname: str, element: Tag, element_id: str) -> str:
        """
        This method sets up the initial script used for dynamically creating elements
        :param random_element_varname: The name of the variable
        :param element: The BeautifulSoup element
        :param element_id: The element id
        :return: The script used for creating elements
        """
        element_name = element.name
        # Escape double quotes since we are wrapping the value in double quotes
        if '"' in element_name:
            element_name = element_name.replace('"', "'")
        # NOTE: There is a regex ELEMENT_INDEX_REGEX that depends on this variable value
        create_element_script = (
            f'const {random_element_varname} = document.createElement("{element_name}");\n'
            f'{random_element_varname}.setAttribute("id", "{element_id}");\n'
        )
        return create_element_script

    @staticmethod
    def _append_element_script(element: Tag, set_of_variable_names: Set[str], random_element_varname: str) -> str:
        """
        This method adds script that appends the element
        :param element: The BeautifulSoup element
        :param set_of_variable_names: A set containing all variable names
        :param random_element_varname: The name of the variable
        :return: The script used for appending elements
        """
        # Based on the parent, we want to append the child correctly
        if element.parent and element.parent.name not in ["[document]", "html", "body", "head"]:
            parent_id = element.parent.attrs.get("id")
            if parent_id and parent_id in set_of_variable_names:
                # If the parent has already been created and we have the id, append this element to the parent
                return f'document.getElementById("{parent_id}").appendChild({random_element_varname});\n'

        return f"document.body.appendChild({random_element_varname});\n"

    def _set_element_innertext_script(self, element: Tag, random_element_varname: str) -> str:
        """
        This method sets the element value to the innerText attribute of the element
        :param element: The BeautifulSoup element
        :param random_element_varname: The name of the variable
        :return: The script used for setting the innerText attribute of an element
        """
        element_value = self._determine_element_value(element)

        # Only set innerText field if there is a value to set it to
        # We do not want to set the innerText field for an html element though...
        if element_value and element.name not in ["html"]:
            # Escape backslashes since they are handled differently in Python strings than in HTML
            if "\\" in element_value:
                element_value = element_value.replace("\\", "\\\\")
            # Escape double quotes since we are wrapping the value in double quotes
            if '"' in element_value:
                element_value = element_value.replace('"', '\\"')
            if element_value.startswith(CDATA_START) and element_value.endswith(CDATA_END):
                element_value = element_value[9:-3]

            # Catch long base64-encoded strings set in weird element attributes
            if not self.weird_base64_value_set and len(element_value) > 2000:
                match = re.match(BASE64_RE, element_value.encode())
                if match and match.group(0) == element_value.encode():
                    self.weird_base64_value_set = True

            return f'{random_element_varname}.innerText = "{element_value}";\n'

        return ""

    @staticmethod
    def _set_element_attribute_script(attr_id: str, attr_val: str, random_element_varname: str) -> str:
        """
        This method sets an element attribute via script
        :param attr_id: The ID of the attribute
        :param attr_val: The value of the attribute
        :param random_element_varname: The name of the variable
        :return: The script used for setting an element's attribute
        """
        if attr_id == "id":
            return ""

        # Please don't put double quotes in attributes people!
        attr_id = attr_id.replace('"', "")
        if not attr_id:
            return ""

        # JavaScript does not like when there are newlines when setting attributes
        if isinstance(attr_val, str) and "\n" in attr_val:
            attr_val = attr_val.replace("\n", "")
        elif isinstance(attr_val, list) and attr_id == "class" and len(attr_val) == 1:
            attr_val = attr_val[0]
        elif isinstance(attr_val, list):
            attr_val = " ".join(attr_val)

        # Escape double quotes since we are wrapping the value in double quotes
        if '"' in attr_val:
            attr_val = attr_val.replace('"', '\\"')

        if "\\" in attr_val and "url(" not in attr_val:
            attr_val = attr_val.replace("\\", "\\\\")

        return f'{random_element_varname}.setAttribute("{attr_id}", "{attr_val}");\n'

    @staticmethod
    def _handle_object_elements(element: Tag, request: ServiceRequest, random_element_varname: str) -> str:
        """
        This method handles "object" elements and could return a script that clicks the object
        :param element: The BeautifulSoup element
        :param request: The ServiceRequest object
        :param random_element_varname: The name of the variable
        :return: The script used for clicking the object
        """
        # <param> tags are equally as special as <object> tags
        # https://developer.mozilla.org/en-US/docs/Web/HTML/Element/param
        # Objects with ShortCut commands are very interesting as per:
        # https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/shortcut
        if element.name == "object":
            is_shortcut = False
            command = None
            # We need to handle <param> tags accordingly
            for descendant in element.descendants:
                if descendant and descendant.name == "param":
                    if all(item in descendant.attrs for item in ["name", "value"]):
                        name = descendant.attrs["name"].lower()
                        value = descendant.attrs["value"]
                        if name == "command" and value.lower() == "shortcut":
                            is_shortcut = True
                        elif name == "item1":
                            command_args = value.split(",")
                            if (
                                len(command_args) >= 2
                                and not command_args[0].strip()
                                and command_args[1].strip() != "cmd.exe"
                            ):
                                # This is the default when loaded on Windows
                                command_args[0] = "cmd.exe"
                            command = " ".join([command_arg for command_arg in command_args if command_arg])
            if is_shortcut and command:
                # JavaScript does not like when there are newlines when setting attributes
                if isinstance(command, str) and "\n" in command:
                    command = command.replace("\n", "")
                if "\\" in command:
                    command = command.replace("\\", "\\\\")
                if '"' in command:
                    command = command.replace('"', '\\"')

                heur = Heuristic(9)
                _ = ResultTextSection(heur.name, heuristic=heur, parent=request.result, body=heur.description)

                # ShortCuts have a click method that we must instantiate.
                return (
                    f'{random_element_varname}.click = function() {{ ws = new {WSHSHELL}(); ws.exec("{command}")}};\n'
                )

        return ""

    def _setup_create_element_script(
        self, element: Tag, element_id: str, set_of_variable_names: Set[str], request: ServiceRequest
    ) -> str:
        """
        This method sets up the script that creates elements dynamically
        :param element: The BeautifulSoup element
        :param element_id: The element id
        :param set_of_variable_names: A set containing all variable names
        :param request: The ServiceRequest object
        :return: The script that creates elements dynamically
        """
        # First get the name of the variable
        random_element_varname = self._determine_element_varname(element, element_id, set_of_variable_names)

        # Initialize the script
        create_element_script = self._initialize_create_element_script(random_element_varname, element, element_id)

        # Add the code to the script that appends the element
        create_element_script += self._append_element_script(element, set_of_variable_names, random_element_varname)

        # Set the innerText attribute of the element to the element value
        create_element_script += self._set_element_innertext_script(element, random_element_varname)

        # Set the other attributes of the element
        for attr_id, attr_val in element.attrs.items():
            create_element_script += self._set_element_attribute_script(attr_id, attr_val, random_element_varname)

        # Handle specific elements that are "object" types
        create_element_script += self._handle_object_elements(element, request, random_element_varname)

        return create_element_script

    def _is_vb_and_js_scripts(
        self, scripts: ResultSet[Tag], request: ServiceRequest
    ) -> Tuple[bool, Optional[ResultTextSection]]:
        """
        This method determines if there is a combination of VisualBasic and JavaScript scripts
        :param scripts: A list of Script soup elements
        :param request: The ServiceRequest object
        :return: A tuple containing a flag indicating if both VisualBasic and JavaScript scripts exist,
                 and a possible result section
        """
        # The combination of both VB and JS existing in an HTML file could be sketchy, stay tuned...
        vb_scripts = [script for script in scripts if is_vb_script(script)]

        js_scripts = any(is_js_script(script) for script in scripts)
        vb_and_js_scripts = bool(vb_scripts) and js_scripts

        if vb_and_js_scripts:
            heur = Heuristic(12)
            vb_and_js_section = ResultTextSection(
                heur.name, heuristic=heur, parent=request.result, body=heur.description
            )
            vb_and_js_section.add_tag("file.behavior", heur.name)

            # We want to extract all VBScripts IFF there are both JavaScript and VBScript scripts in the file
            for script in vb_scripts:
                # Make sure there is actually a body to the script
                body = script.string if script.string is None else str(script.string).strip()

                if body and len(body) > 2:
                    with tempfile.NamedTemporaryFile(dir=self.working_directory, delete=False) as out:
                        out.write(body.encode())
                        vbscript_to_extract = out.name
                    vbs_file_name = f"{get_id_from_data(body.encode())}.vbs"
                    artifact = {
                        "name": vbs_file_name,
                        "path": vbscript_to_extract,
                        "description": "Extracted VBScript Contents",
                        "to_be_extracted": True,
                    }
                    self.log.debug(f"Adding extracted VBScript: {vbs_file_name}")
                    self.artifact_list.append(artifact)
        else:
            vb_and_js_section = None

        return vb_and_js_scripts, vb_and_js_section

    def _is_script_source(self, script: Tag) -> bool:
        """
        This method the script source, if it exists, and adds it to the set
        :param script: The Script soup element
        :return: A flag indicating if a script source was added
        """
        source_added = False
        if script.get("src") and script["src"] not in self.initial_script_sources:
            if is_url(script["src"].encode()):
                if self.gauntlet_runs < 2:
                    self.initial_script_sources.add(script["src"])
                else:
                    self.subsequent_script_sources.add(script["src"])
                source_added = True
            else:
                # Sometimes a script could have a src=the base64-encoded "body" of a script
                # So technically a source was added, but it's not a script source that we want to flag as such
                matches = re.match(APPENDCHILD_BASE64_REGEX, script["src"])
                if matches and len(matches.regs) == 2:
                    try:
                        _ = b64decode(matches.group(1).encode())
                        source_added = True
                    except BinasciiError as e:
                        self.log.debug(
                            f"Could not base64-decode an script src/href value '{matches.group(1)}' due to '{e}'"
                        )

        return source_added

    def _handle_vbscript(
        self,
        body: str,
        js_content: bytes,
        aggregated_js_script: Optional[tempfile.NamedTemporaryFile],
        function_varname: Optional[str],
        vb_and_js_section: Optional[ResultTextSection],
    ) -> Tuple[bytes, Optional[tempfile.NamedTemporaryFile]]:
        """
        This method handles VisualBasic scripts
        :param body: The VisualBasic script body to be looked through
        :param js_content: The file content of the NamedTemporaryFile
        :param aggregated_js_script: The NamedTemporaryFile object
        :param function_varname: The name of the variable pointing at the new Function
        :param vb_and_js_section: The ResultSection that will contain the subsection detailing the IOCs +
               heuristic + signature for URIs
        :return: A tuple of the file contents of the NamedTemporaryFile object and the NamedTemporaryFile object
        """
        # We want to include VBScript code in the JavaScript file to be run, for posperity's sake
        js_content, aggregated_js_script = self._create_vbscript_element(body, js_content, aggregated_js_script)

        # This code is used for converting simple VBScript to JavaScript

        # First, look for any static variables being assigned
        js_content, aggregated_js_script = self._convert_vb_static_variables(body, js_content, aggregated_js_script)

        # Look for WScript Shell usage in VBScript code
        wscript_varname, js_content, aggregated_js_script = self._convert_vb_wscript_shell_declaration(
            body, js_content, aggregated_js_script
        )

        # Use this clause to convert simple WScript.Shell actions
        if wscript_varname:
            # Look for WScript RegWrite usage in VBScript code
            js_content, aggregated_js_script = self._convert_vb_regwrite(
                wscript_varname, body, js_content, aggregated_js_script
            )

        # If a Function is used in JavaScript, but attempted to be run in VBScript
        if function_varname and function_varname in body:
            js_content, aggregated_js_script = self._convert_vb_function_call(
                function_varname, body, vb_and_js_section, js_content, aggregated_js_script
            )

        return js_content, aggregated_js_script

    def _create_vbscript_element(
        self, body: str, js_content: bytes, aggregated_js_script: Optional[tempfile.NamedTemporaryFile]
    ) -> Tuple[bytes, Optional[tempfile.NamedTemporaryFile]]:
        """
        This method takes the body of a VBScript and creates an element in the DOM, basically as a placeholder
        since we cannot run this script in Node.js
        :param body: The VisualBasic script body to be looked through
        :param js_content: The file content of the NamedTemporaryFile
        :param aggregated_js_script: The NamedTemporaryFile object
        :return: A tuple of the file contents of the NamedTemporaryFile object and the NamedTemporaryFile object
        """
        element_name = f"vbscript_{get_id_from_data(body.encode())}"
        element_value = body

        # Escape backslashes since they are handled differently in Python strings than in HTML
        if "\\" in element_value:
            element_value = element_value.replace("\\", "\\\\")
        # Escape double quotes since we are wrapping the value in double quotes
        if '"' in element_value:
            element_value = element_value.replace('"', '\\"')
        # Colons act as a line separator in VBScript so we're going to replace newlines with colons so that the
        # JavaScript doesn't get messed up
        element_value = element_value.strip().replace("\n", " : ")

        create_element_script = (
            f"// The following VBScript is never run and is included for informational purposes\n"
            f'const {element_name} = document.createElement("script");\n'
            f'{element_name}.setAttribute("language", "vbscript");\n'
            f'{element_name}.setAttribute("innerText", "{element_value}");\n'
        )
        js_content, aggregated_js_script = self.insert_content(create_element_script, js_content, aggregated_js_script)
        return js_content, aggregated_js_script

    @staticmethod
    def _modify_javascript_body(body: str) -> str:
        """
        This method modifies the body of the JavaScript
        :param body: The contents of the script
        :return: The modified body of the script
        """
        if body.startswith(CDATA_START) and body.endswith(CDATA_END):
            body = body[9:-3]
        if WSHSHELL in body:
            body = body.replace(WSHSHELL, WSHSHELL.lower())

        # Looks like we have some malformed JavaScript, let's try to fix it up
        if body.rstrip() and body.rstrip()[-1] == "=":
            body = body + '""'

        # If the body does not end with a semi-colon, add one
        if body.rstrip() and body.rstrip()[-1] != ";":
            body = body + ";"

        return body

    @staticmethod
    def _handle_onevent_attributes(is_script_body: bool, element: Tag, onevents: List[str]) -> Tuple[bool, List[str]]:
        """
        This method
        """
        # Supported by https://github.com/target/strelka/blob/3439953e6aa2dafb68ea73c3977da11f87aeacdf/src/python/strelka/scanners/scan_javascript.py#L37:L39
        # Look for elements with the on<event> attributes and add their script bodies to the aggregated js script
        for event in ["error", "pageshow", "load", "submit", "click", "finish"]:
            for onevent in element.get_attribute_list(f"on{event}"):
                if onevent:
                    is_script_body = True

                    if onevent.startswith("return "):
                        onevent = onevent.replace("return ", "")

                    if onevent not in onevents:
                        onevents.append(onevent)

        return is_script_body, onevents

    def _handle_misparsed_soup(
        self,
        body: str,
        aggregated_js_script: Optional[tempfile.NamedTemporaryFile],
        js_content: bytes,
        request: ServiceRequest,
    ) -> Tuple[str, Optional[tempfile.NamedTemporaryFile], bytes]:
        """
        If there is a malformed JavaScript script and another "script body" starts with an already seen script,
        this is most likely a parsing issue and we are going to slice the already seen script out
        :param body: The body of the script that we will determine if it is mis-parsed
        :param aggregated_js_script: The NamedTemporaryFile object
        :param js_content: The file content of the NamedTemporaryFile
        :param request: An instance of the ServiceRequest object
        :return: A tuple of the JavaScript file that was written,
                 the contents of the file that was written and the correct script body
        """

        if self.malformed_javascript and any(
            body.startswith(body_script) and body != body_script for body_script in self.scripts
        ):
            for body_script in self.scripts.copy():
                if body.startswith(body_script) and body != body_script:
                    start_idx = body.rfind(body_script) + len(body_script)
                    remainder = body[start_idx:]
                    # Mis-parsed remainder of body, to be extracted
                    try:
                        misparsed_soup = BeautifulSoup(remainder, features="html5lib")
                    except Exception:
                        # Swing and a miss
                        break

                    # We want to add this code above the divider because it is auto-generated
                    aggregated_js_script, js_content = self._extract_js_using_soup(
                        misparsed_soup, aggregated_js_script, js_content, request, insert_above_divider=True
                    )

                    body = body_script

        else:
            self.scripts.add(body)

        return aggregated_js_script, js_content, body

    def _handle_malformed_javascript(
        self,
        visible_texts: ResultSet[Tag],
        aggregated_js_script: Optional[tempfile.NamedTemporaryFile],
        js_content: bytes,
    ) -> Tuple[Optional[tempfile.NamedTemporaryFile], bytes]:
        """
        This is a workaround for broken scripts that we still want to run. Odds are this won't create
        valid JavaScript, but odds are the initial JavaScript wasn't valid in the first place, so we're just going to
        append the commented out the code and try again.
        :param visible_texts:
        :param aggregated_js_script: The NamedTemporaryFile object
        :param js_content: The file content of the NamedTemporaryFile
        :return: A tuple of the JavaScript file that was written and the contents of the file that was written
        """

        for visible_text in visible_texts:
            malformed_javascript = visible_text.string.strip()

            if not malformed_javascript:
                continue

            # Writing the malformed javascript to a file so that we can use Identify's fileinfo
            with tempfile.NamedTemporaryFile(dir=self.working_directory, delete=False) as out:
                out.write(malformed_javascript.encode())
                malformed_path = out.name
            file_type_details = self.identify.fileinfo(malformed_path, generate_hashes=False)
            file_type = file_type_details["type"]

            if file_type == "text/javascript" or "document.write" in malformed_javascript:
                self.malformed_javascript = True

                # Commenting it out so that it doesn't actually run
                commented_out_malformed_javascript = f"/*\n{malformed_javascript}\n*/"
                js_content, aggregated_js_script = self.append_content(
                    commented_out_malformed_javascript, js_content, aggregated_js_script
                )

                if file_type != "text/javascript":
                    for regex in [DOM_WRITE_UNESCAPE_REGEX, DOM_WRITE_ATOB_REGEX]:
                        dom_write_match = re.search(regex, malformed_javascript, re.IGNORECASE)
                        if dom_write_match:
                            self.log.debug(f"Malformed JavaScript was found using {regex}...")
                            js_content, aggregated_js_script = self.append_content(
                                dom_write_match.group(1), js_content, aggregated_js_script
                            )
                else:
                    self.log.debug(f"Should we add '{malformed_javascript}' to the JavaScript file uncommented?")
        return js_content, aggregated_js_script

    def _extract_js_using_soup(
        self,
        soup: BeautifulSoup,
        aggregated_js_script: Optional[tempfile.NamedTemporaryFile] = None,
        js_content: bytes = b"",
        request: Optional[ServiceRequest] = None,
        insert_above_divider: bool = False,
    ) -> Tuple[Optional[tempfile.NamedTemporaryFile], Optional[bytes]]:
        """
        This method extracts JavaScript from BeautifulSoup enumeration
        :param soup: The BeautifulSoup object
        :param aggregated_js_script: The NamedTemporaryFile object
        :param js_content: The file content of the NamedTemporaryFile
        :param request: An instance of the ServiceRequest object
        :param insert_above_divider: A flag indicating if we have more code that is going to be programmatically created
        :return: A tuple of the JavaScript file that was written and the contents of the file that was written
        """

        # A list of methods to run when a form is submitted, after the DOM is loaded
        onevents: List[str] = list()

        self.log.debug("Extracting JavaScript from soup...")
        scripts = soup.findAll("script")
        visible_texts = self._extract_visible_text_from_soup(soup)

        self._contains_scripts_with_unescape(soup, scripts)

        # We need this flag since we are now creating most HTML elements dynamically,
        # and there is a chance that an HTML file has no JavaScript to be run.
        is_script_body = False

        # Create most HTML elements with JavaScript
        elements = soup.findAll()
        bodies = soup.findAll("body")
        body_children: List[str] = []
        for body in bodies:
            body_children.extend(
                [child.name for child in body.children if child.name]
                + [descendant.name for descendant in body.descendants if descendant.name]
            )
        if not body_children and not self.low_body_elements:
            self.low_body_elements = True

        # This will hold all variable names, to ensure we avoid variable name collision
        set_of_variable_names: Set[str] = set()
        for index, element in enumerate(elements):
            # Don't add an element to the script if it matches certain criteria
            if self._skip_element(element):
                continue

            # Massage the element attributes
            element = self._remove_safelisted_element_attrs(element)

            # Get the last index and use it to determine the element id
            idx = self._determine_last_index(index, insert_above_divider, js_content)
            element_id = self._determine_element_id(element, idx, set_of_variable_names)
            set_of_variable_names.add(element_id)

            # This is the $$$ section
            create_element_script = self._setup_create_element_script(
                element, element_id, set_of_variable_names, request
            )

            if insert_above_divider:
                js_content, aggregated_js_script = self.insert_content(
                    create_element_script, js_content, aggregated_js_script
                )
            else:
                js_content, aggregated_js_script = self.append_content(
                    create_element_script, js_content, aggregated_js_script
                )

            (
                is_script_body,
                onevents,
            ) = self._handle_onevent_attributes(is_script_body, element, onevents)

        if js_content and not insert_above_divider:
            # Add a break that is obvious for JS-X-Ray to differentiate
            js_content, aggregated_js_script = self.append_content(DIVIDING_COMMENT, js_content, aggregated_js_script)

        # Used for passed Function between VBScript and JavaScript
        function_varname = None

        vb_and_js_scripts, vb_and_js_section = self._is_vb_and_js_scripts(scripts, request)
        url_sec = None

        for script in scripts:
            source_added = self._is_script_source(script)

            # Make sure there is actually a body to the script
            body = script.string if script.string is None else str(script.string).strip()

            if body is None or len(body) <= 2:
                if source_added:
                    # Sometimes a script could have a src=the base64-encoded "body" of a script
                    # So technically a source was added, but it's not a script source that we want to flag as such
                    # Pop the body out and continue running the gauntlet
                    matches = re.match(APPENDCHILD_BASE64_REGEX, script["src"])
                    if matches and len(matches.regs) == 2:
                        try:
                            body = b64decode(matches.group(1).encode()).decode()
                        except BinasciiError as e:
                            self.log.debug(
                                f"Could not base64-decode an script src/href value '{matches.group(1)}' due to '{e}'"
                            )
                    else:
                        self.script_with_source_and_no_body = True

                if not body:
                    continue

            # Inspired by https://github.com/viper-framework/viper-modules/blob/00ee6cd2b2ad4ed278279ca9e383e48bc23a2555/htmlparser.py#L68
            script_entropy = calculate_partition_entropy(BytesIO(body.encode()))
            if script_entropy[0] >= 4:
                self.script_entropies[get_id_from_data(body)] = {
                    "preview": truncate(body, 50),
                    "entropy": script_entropy,
                }

            if is_vb_script(script):
                js_content, aggregated_js_script = self._handle_vbscript(
                    body, js_content, aggregated_js_script, function_varname, vb_and_js_section
                )
                continue

            if is_js_script(script):
                # BeautifulSoup has failed us, don't add this as it will break JavaScript compilation
                if body.startswith("<script "):
                    continue
                aggregated_js_script, js_content, body = self._handle_misparsed_soup(
                    body, aggregated_js_script, js_content, request
                )

                # If there is no "type" attribute specified in a script element, then the default assumption is
                # that the body of the element is Javascript
                is_script_body = True

                if vb_and_js_scripts:
                    # Look for Function usage in JavaScript, because it may be used in VBScript later on in an HTML file
                    function_varname = self._find_js_function_declaration(body)

                    url_sec = self._look_for_iocs_between_vb_and_js(body, vb_and_js_section, url_sec)

                body = self._modify_javascript_body(body)

                js_content, aggregated_js_script = self.append_content(body, js_content, aggregated_js_script)

        js_content, aggregated_js_script = self._handle_malformed_javascript(
            visible_texts, aggregated_js_script, js_content
        )

        if soup.body:
            is_script_body, onevents = self._handle_onevent_attributes(is_script_body, soup.body, onevents)

        for onevent in onevents:
            js_content, aggregated_js_script = self.append_content(onevent, js_content, aggregated_js_script)

        return aggregated_js_script, js_content

    def _extract_css_using_soup(
        self,
        soup: BeautifulSoup,
        request: ServiceRequest,
        aggregated_js_script: tempfile.NamedTemporaryFile,
        js_content: bytes,
    ) -> Tuple[Optional[tempfile.NamedTemporaryFile], Optional[tempfile.NamedTemporaryFile], Optional[bytes]]:
        """
        This method extracts CSS and possibly JS from BeautifulSoup enumeration
        :param soup: The BeautifulSoup object
        :param request: The ServiceRequest object
        :param aggregated_js_script: The NamedTemporaryFile object of the JS script
        :param js_content: The file content of the NamedTemporaryFile of the JS script
        :return: A tuple of the name of the CSS script, the JavaScript file that was written and the contents of the
                 file that was written
        """
        self.log.debug("Extracting CSS from soup...")

        # Payloads can be hidden in the CSS, so we should try to extract these values and pass them to our JavaScript
        # analysis envs
        try:
            styles = soup.findAll("style")
            style_json = dict()
            css_content = b""
            aggregated_css_script = None
            for style in styles:
                # Make sure there is actually a body to the script
                body = style.string
                if body is None:
                    continue
                body = str(body).strip()  # Remove whitespace

                css_content, aggregated_css_script = self.append_content(body, css_content, aggregated_css_script)

                # If has been observed that BeautifulSoup has difficulty parsing CSS,
                # and JavaScript can be embedded within a Style element. Therefore, try to extract and aggregate!
                file_type_details = self.identify.fileinfo(aggregated_css_script.name, generate_hashes=False)
                file_type = file_type_details["type"]
                if file_type in ["code/html", "code/hta", "image/svg"]:
                    css_body_soup = BeautifulSoup(body, features="html5lib")
                    aggregated_js_script, js_content = self._extract_js_using_soup(
                        css_body_soup, aggregated_js_script, js_content, request, insert_above_divider=True
                    )

                # Parse CSS to JSON
                qualified_rules = parse_stylesheet(body, skip_comments=True, skip_whitespace=True)
                for qualified_rule in qualified_rules:
                    if qualified_rule.type == "at-rule":
                        qualified_rule = tinycss2_helper.consume_at_rule(qualified_rule, qualified_rule.content)
                    preludes = tinycss2_helper.significant_tokens(qualified_rule.prelude)
                    if len(preludes) > 1:
                        prelude_name = "".join([prelude.value for prelude in preludes])
                        self.log.debug(
                            f"Combine all preludes to get the declaration name: \
                                {[prelude.value for prelude in preludes]} -> {prelude_name}"
                        )
                    else:
                        # If a function block is the prelude, use the lower_name, not the value
                        prelude_name = preludes[0].value if hasattr(preludes[0], "value") else preludes[0].lower_name
                    if hasattr(qualified_rule, "content") and qualified_rule.content:
                        output = tinycss2_helper.parse_declaration_list(
                            qualified_rule.content, skip_comments=True, skip_whitespace=True
                        )
                        style_json[prelude_name] = output

            if aggregated_css_script is None:
                return None, aggregated_js_script, js_content

            aggregated_css_script.close()

            if style_json:
                artifact = {
                    "name": "temp_css.css",
                    "path": aggregated_css_script.name,
                    "description": "Extracted CSS",
                    "to_be_extracted": False,
                }
                self.log.debug("Adding extracted CSS: temp_css.css")
                self.artifact_list.append(artifact)
                css_script_name = aggregated_css_script.name

                # Look for suspicious CSS usage
                for _, rules in style_json.items():
                    for rule in rules:
                        declaration_blocks = rule.values()
                        for declaration_block in declaration_blocks:
                            for item in declaration_block.get("values", []):
                                if isinstance(item, dict):
                                    if item.get("url"):
                                        # SUS
                                        url_path = None
                                        # If the content is base64 encoded, decode it before we extract it
                                        matches = re.match(APPENDCHILD_BASE64_REGEX, item["url"])
                                        if matches and len(matches.regs) == 2:
                                            item["url"] = b64decode(matches.group(1).encode())
                                        else:
                                            item["url"] = item["url"].encode()
                                        with tempfile.NamedTemporaryFile(
                                            dir=self.working_directory, delete=False, mode="wb"
                                        ) as t:
                                            t.write(item["url"])
                                            url_path = t.name
                                        artifact = {
                                            "name": get_sha256_for_file(url_path),
                                            "path": url_path,
                                            "description": "URL value from CSS",
                                            "to_be_extracted": True,
                                        }
                                        self.log.debug(f"Extracting URL value from CSS: {url_path}")
                                        self.artifact_list.append(artifact)
                                        heur = Heuristic(7)
                                        _ = ResultTextSection(
                                            heur.name, heuristic=heur, parent=request.result, body=heur.description
                                        )
            else:
                css_script_name = None
        except Exception as e:
            # It's not the end of the world if we cannot parse the CSS... this is JsJaws after all!
            self.log.debug(f"Could not parse CSS due to {e}.")
            css_script_name = None

        return css_script_name, aggregated_js_script, js_content

    def _extract_visible_text_from_soup(self, soup: BeautifulSoup) -> List[str]:
        """
        This method extracts visible text from the HTML page, given soup object
        :param dom_content: The content of written to the DOM
        :return: A list of visible text that was written to the DOM
        """
        self.log.debug("Extracting visible text from soup...")

        # Extract password from visible text, taken from https://stackoverflow.com/a/1983219
        def tag_visible(element):
            if element.parent.name in ["style", "script", "head", "title", "meta", "[document]"]:
                return False
            if isinstance(element, Comment):
                return False
            return True

        visible_texts = [x for x in filter(tag_visible, soup.findAll(text=True))]
        return visible_texts

    def _extract_visible_text_using_soup(self, dom_content) -> List[str]:
        """
        This method extracts visible text from the HTML page, given DOM content
        :param dom_content: The content of written to the DOM
        :return: A list of visible text that was written to the DOM
        """
        try:
            soup = BeautifulSoup(dom_content, features="html5lib")
        except Exception:
            # If the written text is not an HTML document, return it
            return [dom_content]

        return self._extract_visible_text_from_soup(soup)

    def _extract_wscript(self, output: List[str], result: Result) -> None:
        """
        This method does a couple of things:
        1. It looks for lines from the output that contain shell scripts, and writes these to a file for extraction
        2. It attempts to extract IOCs from these shell scripts
        :param output: A list of strings where each string is a line of stdout from the MalwareJail tool
        :param result: A Result object containing the service results
        :return: None
        """
        self.log.debug("Extract WScript commands...")
        batch_cmd_spotted = False
        ps1_cmd_spotted = False

        wscript_batch_extraction = open(self.extracted_wscript_batch_path, "a+")
        wscript_ps1_extraction = open(self.extracted_wscript_ps1_path, "a+")
        wscript_batch_extraction.write(CUSTOM_BATCH_ID.decode())
        wscript_ps1_extraction.write(CUSTOM_PS1_ID.decode())

        wscript_res_sec = ResultTableSection("IOCs extracted from WScript")
        pre_rows = 0
        post_rows = 0
        for line in output:
            wscript_shell_run = re.search(WSCRIPT_SHELL_REGEX, line, re.IGNORECASE)
            # Script was run
            if wscript_shell_run:
                cmd = wscript_shell_run.group(1)
                # This is a byproduct of the sandbox using WScript.Shell.Run
                # https://ss64.com/vb/run.html
                # intWindowStyle = (optional) any integer from 0-10. 0 is a hacker favourite (hide the
                # window and activate another
                # window), although we have seen 1 before (activate and display the window)
                # bWaitOnReturn = boolean
                if ".run" in line.lower():
                    for intWindowStyle in range(12):
                        for bWaitOnReturn in ["undefined", "false", "true", "0", "1"]:
                            # Since intWindowsStyle is optional, add a clause here
                            if intWindowStyle == 11:
                                item = f", {bWaitOnReturn}"
                            else:
                                item = f", {intWindowStyle}, {bWaitOnReturn}"
                            if cmd.endswith(item):
                                cmd = cmd.replace(item, "")

                # Shell.Application's ShellExecute lists the cmd in a comma-delimited list. So we need to
                # handle accordingly.
                elif ".shellexecute" in line.lower():
                    # https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-showwindow
                    for nCmdShow in range(12):
                        # https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecutea#parameters
                        for lpOperation in ["edit", "expore", "find", "open", "print", "runas"]:
                            # Since nCmdShow is optional, add a clause here
                            if nCmdShow == 11:
                                item = f', "{lpOperation}"'
                            else:
                                item = f', "{lpOperation}", {nCmdShow}'
                            if cmd.endswith(item):
                                cmd = cmd.replace(item, "")

                    cmd = " ".join(cmd.split('", "'))

                # This is a byproduct of using ProxyGenerator for WScript
                if cmd.startswith('"') and cmd.endswith('"'):
                    cmd = cmd[1:-1]

                wscript_res_sec.add_tag("dynamic.process.command_line", cmd)

                # We want to extract powershell commands to a powershell file, which can be confirmed using multidecoder
                try:
                    matches = find_powershell_strings(cmd.encode())
                except BinasciiError as e:
                    self.log.debug(f"Could not base64-decode encoded command value '{cmd}' due to '{e}'")
                    matches = []

                if matches:
                    for match in matches:
                        powershell_command = get_powershell_command(match.value)
                        wscript_ps1_extraction.write(powershell_command.decode().strip() + "\n")
                        ps1_cmd_spotted = True
                else:
                    # Write non-ps1 to file
                    wscript_batch_extraction.write(cmd.strip() + "\n")
                    batch_cmd_spotted = True

                # Let's try to extract IOCs from it

                if wscript_res_sec.body:
                    pre_rows = len(wscript_res_sec.section_body.body)

                # These IOC tags should be dynamic because the WScript Shell faked running a command
                extract_iocs_from_text_blob(line, wscript_res_sec)

                if wscript_res_sec.body:
                    post_rows = len(wscript_res_sec.body)

                # If an IOC was added, raise a heuristic
                if pre_rows < post_rows:
                    if wscript_res_sec.heuristic is None:
                        wscript_res_sec.set_heuristic(13)

                    # If Wscript.Shell uses PowerShell AND an IOC was found, this is suspicious
                    if any(cmd.lower().strip().startswith(ps1) for ps1 in POWERSHELL_VARIATIONS):
                        wscript_res_sec.heuristic.add_signature_id("wscript_pwsh_url", 500)
                    # If Wscript.Shell uses CMD AND an IOC was found, this is suspicious
                    elif any(cmd.lower().strip().startswith(cp) for cp in COMMAND_VARIATIONS):
                        wscript_res_sec.heuristic.add_signature_id("wscript_cmd_url", 500)
                    # If Wscript.Shell uses cURL AND an IOC was found, this is suspicious
                    elif any(cmd.lower().strip().startswith(curl) for curl in CURL_VARIATIONS):
                        wscript_res_sec.heuristic.add_signature_id("wscript_curl_url", 500)
                    # If Wscript.Shell uses bitsadmin AND an IOC was found, this is suspicious
                    elif any(cmd.lower().strip().startswith(bitsadmin) for bitsadmin in BITSADMIN_VARIATIONS):
                        wscript_res_sec.heuristic.add_signature_id("wscript_bitsadmin_url", 500)

        wscript_batch_extraction.close()
        wscript_ps1_extraction.close()

        if batch_cmd_spotted:
            artifact = {
                "name": self.extracted_wscript_batch,
                "path": self.extracted_wscript_batch_path,
                "description": "Extracted WScript batch file",
                "to_be_extracted": True,
            }
            self.log.debug(f"Adding extracted file: {self.extracted_wscript_batch}")
            self.artifact_list.append(artifact)

        if ps1_cmd_spotted:
            artifact = {
                "name": self.extracted_wscript_ps1,
                "path": self.extracted_wscript_ps1_path,
                "description": "Extracted WScript ps1 file",
                "to_be_extracted": True,
            }
            self.log.debug(f"Adding extracted file: {self.extracted_wscript_ps1}")
            self.artifact_list.append(artifact)

        if (batch_cmd_spotted or ps1_cmd_spotted) and wscript_res_sec.body:
            result.add_section(wscript_res_sec)

    def _extract_payloads(self, sample_sha256: str, deep_scan: bool) -> None:
        """
        This method extracts unique payloads that were written to disk by MalwareJail and Box.js
        :param sample_sha256: The SHA256 of the submitted file
        :param deep_scan: A boolean representing if the user has requested a deep scan
        :return: None
        """
        self.log.debug("Extracting payloads...")
        unique_shas = {sample_sha256}
        max_payloads_extracted = self.config.get("max_payloads_extracted", MAX_PAYLOAD_FILES_EXTRACTED)
        extracted_count = 0

        malware_jail_payloads = [
            (file, path.join(self.malware_jail_payload_extraction_dir, file))
            for file in sorted(listdir(self.malware_jail_payload_extraction_dir))
        ]

        # These are dumped files from Box.js of js that was run successfully
        snippet_keys: List[str] = []
        if len(glob(self.boxjs_snippets)) > 0:
            boxjs_snippets = max(glob(self.boxjs_snippets), key=path.getctime)
            with open(boxjs_snippets, "r") as f:
                try:
                    snippet_keys = list(loads(f.read()).keys())
                except JSONDecodeError as e:
                    self.log.debug(f"Could not read {boxjs_snippets} due to {e}.")
                    snippet_keys = []

        box_js_payloads = []
        if len(glob(self.boxjs_output_dir)) > 0:
            boxjs_output_dir = max(glob(self.boxjs_output_dir), key=path.getctime)

            box_js_payloads = []
            for file in sorted(listdir(boxjs_output_dir)):
                if file not in snippet_keys:
                    box_js_payloads.append((file, path.join(boxjs_output_dir, file)))

        all_payloads = malware_jail_payloads + box_js_payloads

        for file, extracted in all_payloads:
            # No empty files
            if path.getsize(extracted) == 0:
                continue
            # These are not payloads
            # Direct paths
            if extracted in [
                self.malware_jail_urls_json_path,
                self.extracted_wscript_batch_path,
                self.extracted_wscript_ps1_path,
                self.boxjs_batch_path,
                self.boxjs_ps1_path,
            ]:
                continue
            # Glob paths
            elif any(
                extracted in glob(glob_path)
                for glob_path in [
                    self.boxjs_iocs,
                    self.boxjs_resources,
                    self.boxjs_snippets,
                    self.boxjs_analysis_log,
                    self.boxjs_urls_json_path,
                ]
            ):
                continue
            # If the snippets.json is not finished being written to, there is a race condition here,
            # so let's confirm that the file to be extracted is a snippet but hasn't been written to
            # the snippets.json yet
            elif (
                len(glob(self.boxjs_output_dir)) > 0
                and file in listdir(max(glob(self.boxjs_output_dir), key=path.getctime))
                and re.match(SNIPPET_FILE_NAME, file)
            ):
                continue
            extracted_sha = get_sha256_for_file(extracted)
            if extracted_sha not in unique_shas and extracted_sha not in [RESOURCE_NOT_FOUND_SHA256, FAKE_FILE_CONTENT]:
                extracted_count += 1
                if not deep_scan and extracted_count > max_payloads_extracted:
                    self.log.debug(f"The maximum number of payloads {max_payloads_extracted} were extracted.")
                    return
                unique_shas.add(extracted_sha)
                # Consistency!
                if re.match(BOX_JS_PAYLOAD_FILE_NAME, file):
                    file = extracted_sha
                artifact = {
                    "name": safe_str(file),
                    "path": extracted,
                    "description": "Extracted Payload",
                    "to_be_extracted": True,
                }
                self.log.debug(f"Adding extracted file: {safe_str(file)}")
                self.artifact_list.append(artifact)

    def _parse_malwarejail_output(self, output: List[str]) -> str:
        """
        This method is a generator that validates whether a new line of malwarejail output exists
        :param output: All malwarejail output
        :return: None
        """
        # ret represents the value to be yielded
        ret = None
        for line in output:
            if not isinstance(line, str):
                continue
            if line.startswith("[") and "] " in line:
                try:
                    timestamp = re.match(MALWARE_JAIL_TIME_STAMP, line)
                    if not timestamp:
                        continue
                    if len(timestamp.regs) < 2:
                        continue
                    dtparse(timestamp.group(1))
                    if ret is not None:
                        yield ret
                    # We have a valid timestamp match but nothing to yield
                    ret = ""
                except ValueError:
                    pass
            if ret:
                ret = f"{ret}\n"
            if not ret:
                ret = f"{line}"
                continue
            ret = f"{ret}{line}"
        if ret is not None:
            yield ret

    def _extract_doc_writes(self, output: List[str], request: ServiceRequest, original_contents: bytes) -> None:
        """
        This method writes all document writes to a file and adds that in an extracted file
        :param output: A list of strings where each string is a line of stdout from the MalwareJail tool
        :param request: The ServiceRequest object
        :param original_contents: the original contents for the request file
        :return: None
        """
        doc_write = False
        content_to_write_list = []
        for line in self._parse_malwarejail_output(output):
            # The document.write has been seen and the following lines are the content
            if doc_write:
                written_content = line.split("] => '", 1)[1].strip()[:-1]
                content_to_write_list.append(written_content)
                doc_write = False

            # The content from a document write is going to start on the next line if there is a match here
            # This should cover both document.write(content) and document.writeln(content)
            if all(item in line.split("] ", 1)[1][:40] for item in ["document", "write", "(content)"]):
                doc_write = True

        if not content_to_write_list:
            return

        # Do not join by newline because that is not how a browser interprets multiple document.write calls
        # document.writeln calls will end with a newline in document.js
        content_to_write = "".join(content_to_write_list).encode()
        doc_write_hash = sha256(content_to_write).hexdigest()

        if doc_write_hash in self.doc_write_hashes:
            # To avoid recursive gauntlet runs, perform this check
            self.log.debug("No new content written to the DOM...")

            if self.gauntlet_runs > 1:
                heur = Heuristic(15)
                heur15_res_sec = ResultTextSection(
                    heur.name, heuristic=heur, parent=request.result, body=heur.description
                )

                # Add a signature for the number of times the gauntlet has been run
                if self.gauntlet_runs == 2:
                    heur15_res_sec.heuristic.add_signature_id("dom_writes_equal_2", 0)
                elif self.gauntlet_runs == 3:
                    heur15_res_sec.heuristic.add_signature_id("dom_writes_equal_3")
                elif self.gauntlet_runs in [4, 5]:
                    heur15_res_sec.heuristic.add_signature_id("dom_writes_equal_4_or_5")
                elif self.gauntlet_runs > 5 and self.gauntlet_runs <= 10:
                    heur15_res_sec.heuristic.add_signature_id("dom_writes_between_5_and_10")
                elif self.gauntlet_runs > 10 and self.gauntlet_runs <= 20:
                    heur15_res_sec.heuristic.add_signature_id("dom_writes_between_10_and_20")
                elif self.gauntlet_runs > 20:
                    heur15_res_sec.heuristic.add_signature_id("dom_writes_greater_than_20")
            return

        self.doc_write_hashes.add(doc_write_hash)

        visible_text: Set[str] = set()
        for line in content_to_write_list:
            visible_text.update(self._extract_visible_text_using_soup(line))
        if any(any(WORD in line.lower() for WORD in PASSWORD_WORDS) for line in visible_text):
            new_passwords = set()
            # If the line including "password" was written to the DOM later than when the actual password was, we
            # should look in the file contents for it
            visible_text.update(self._extract_visible_text_using_soup(original_contents))
            for line in visible_text:
                if len(line) > 10000:
                    line = truncate(line, 10000)
                for password in extract_passwords(line):
                    if not password or len(password) > 30:
                        # We assume that passwords exist and won't be that long.
                        continue
                    new_passwords.add(password)

            if new_passwords:
                self.log.debug(f"Found password(s) in the HTML doc: {new_passwords}")
                passwords_extracted_file = "passwords_extracted_from_html.json"
                password_extracted_path = path.join(self.working_directory, passwords_extracted_file)
                with open(password_extracted_path, "w") as f:
                    f.write(dumps(sorted(list(new_passwords))))
                request.add_supplementary(
                    password_extracted_path, passwords_extracted_file, "Passwords extracted from HTML file"
                )
                # It is technically not required to sort them, but it makes the output of the module predictable
                if "passwords" in request.temp_submission_data:
                    new_passwords.update(set(request.temp_submission_data["passwords"]))
                request.temp_submission_data["passwords"] = sorted(list(new_passwords))

        # The entire point of writing elements into the document is to manipulate the DOM. If certain elements
        # contain script elements that depend on previously declared variables, then we should build an HTML
        # file will all content possible and send that through the gauntlet again.

        # If the initial file was identified as JavaScript, and there were elements written to the DOM, then
        # we should wrap the JavaScript with <script> tags so that it is correctly handled by the next run
        # of the gauntlet.
        if self.sample_type == "code/javascript":
            total_dom_contents = b"<script>" + original_contents + b"</script>"
        else:
            total_dom_contents = original_contents
        total_dom_contents += b"\n"
        total_dom_contents += content_to_write
        with tempfile.NamedTemporaryFile(dir=self.working_directory, delete=False) as out:
            out.write(total_dom_contents)
            total_dom_path = out.name

        self.log.debug("There were elements written to the DOM. Time to run the gauntlet again!")
        self._run_the_gauntlet(request, total_dom_path, total_dom_contents, original_contents, subsequent_run=True)

    def _extract_urls(self, request: ServiceRequest) -> None:
        """
        This method extracts the URL interactions from urls.json that is dumped by MalwareJail
        This method also extracts the URL interactions from the IOC.json that is dumped by Box.js
        :param request: The ServiceRequest object
        :return: None
        """
        self.log.debug("Extracting URLs...")
        if not path.exists(self.malware_jail_urls_json_path) and not glob(self.boxjs_iocs):
            return

        urls_result_section = ResultTableSection("URLs")
        urls_result_section.set_column_order(["url", "method", "request_body"])
        urls_rows: List[TableRow] = []
        items_seen: Set[str] = set()
        mj_posts_seen: List[str] = []
        boxjs_posts_seen: List[str] = []

        if path.exists(self.malware_jail_urls_json_path):
            with open(self.malware_jail_urls_json_path, "r") as f:
                file_contents = f.read()
                urls_json = loads(file_contents)
                for item in urls_json:
                    if len(item["url"]) > 500:
                        item["url"] = truncate(item["url"], 500)
                    if not add_tag(urls_result_section, "network.static.uri", item["url"], self.safelist):
                        continue
                    if item.get("method", "").lower() == "post":
                        mj_posts_seen.append(item["url"])
                        params = {"method": "POST", "headers": item.get("headers", {})}
                        if isinstance(item.get("request_body"), dict):
                            params["json"] = item.get("request_body", None)
                        else:
                            params["data"] = item.get("request_body", None)
                        if urlparse(item["url"]).netloc not in COMMON_FP_DOMAINS:
                            self.log.debug(f"Extracting URI file for '{item['url']}'")
                            request.add_extracted_uri("URI accessed via POST", uri=item["url"], params=params)
                    if dumps(item) not in items_seen:
                        items_seen.add(dumps(item))
                        urls_rows.append(TableRow(**item))

        if len(glob(self.boxjs_iocs)) > 0:
            boxjs_iocs = max(glob(self.boxjs_iocs), key=path.getctime)
            with open(boxjs_iocs, "r") as f:
                file_contents = f.read()
                ioc_json: List[Dict[str, Any]] = []
                try:
                    ioc_json = loads(file_contents)
                except JSONDecodeError as e:
                    self.log.warning(f"Failed to json.load() {BOX_JS}'s IOC JSON due to {e}")
                for ioc in ioc_json:
                    value = ioc.get("value", "")
                    if ioc["type"] == "UrlFetch":
                        if any(value["url"] == url["url"] for url in urls_rows):
                            continue
                        elif not add_tag(urls_result_section, "network.dynamic.uri", value["url"], self.safelist):
                            continue
                        item = {"url": value["url"], "method": value["method"], "request_headers": value["headers"]}
                        # For some reason BoxJS allows method to be a string and also a list of strings
                        if (isinstance(item.get("method"), str) and item["method"].lower() == "post") or (
                            isinstance(item.get("method"), list)
                            and len(item["method"]) == 1
                            and any(method == "post" for method in item["method"])
                        ):
                            boxjs_posts_seen.append(value["url"])
                            params = {"method": "POST", "headers": item.get("headers", {})}
                            if isinstance(item.get("request_body"), dict):
                                params["json"] = item.get("request_body", None)
                            else:
                                params["data"] = item.get("request_body", None)
                            if urlparse(item["url"]).netloc not in COMMON_FP_DOMAINS:
                                self.log.debug(f"Extracting URI file for '{item['url']}'")
                                request.add_extracted_uri("URI accessed via POST", uri=item["url"], params=params)
                        if dumps(item) not in items_seen:
                            items_seen.add(dumps(item))
                            urls_rows.append(TableRow(**item))
                        else:
                            continue

        if urls_rows:
            [urls_result_section.add_row(urls_row) for urls_row in urls_rows]
            urls_result_section.set_heuristic(1)

            if self.single_script_with_unescape:
                urls_result_section.heuristic.add_signature_id("single_script_url", 500)
            elif self.multiple_scripts_with_unescape:
                urls_result_section.heuristic.add_signature_id("multiple_scripts_url", 500)

            if self.function_inception:
                urls_result_section.heuristic.add_signature_id("function_inception_url", 500)

            if self.split_reverse_join:
                urls_result_section.heuristic.add_signature_id("split_reverse_join_url", 500)

            if self.weird_base64_value_set:
                urls_result_section.heuristic.add_signature_id("weird_base64_value_set_url", 500)

            if self.embedded_code_in_lib:
                urls_result_section.heuristic.add_signature_id("gootloader_url", 500)

            if self.url_used_for_suspicious_exec:
                urls_result_section.heuristic.add_signature_id("url_used_for_suspicious_exec", 500)

            if self.is_phishing and (mj_posts_seen or boxjs_posts_seen):
                phishing_post_urls_result_section = ResultTextSection(
                    "URLs used for POSTs, found in a file containing suspicious phishing characteristics",
                    parent=urls_result_section,
                )
                phishing_post_urls_result_section.set_heuristic(1)
                for post_seen in mj_posts_seen:
                    phishing_post_urls_result_section.add_line(f"\t-\t{post_seen}")
                    add_tag(phishing_post_urls_result_section, "network.static.uri", post_seen, self.safelist)
                for post_seen in boxjs_posts_seen:
                    phishing_post_urls_result_section.add_line(f"\t-\t{post_seen}")
                    add_tag(phishing_post_urls_result_section, "network.dynamic.uri", post_seen, self.safelist)
                phishing_post_urls_result_section.heuristic.add_signature_id("is_phishing_url", 500)

            # Special case where we are going to flag the GETs because this file is most likely phishing.
            elif self.is_phishing and (
                self.html_document_write and self.sample_type == "code/html" or self.gauntlet_runs > 1
            ):
                urls_result_section.heuristic.add_signature_id("possible_phishing_urls", 400)
            request.result.add_section(urls_result_section)

    def _extract_supplementary(self, output: List[str]) -> None:
        """
        This method adds the sandbox environment dump and the MalwareJail stdout as supplementary files, as well as
        the dumps from Box.js
        :param output: A list of strings where each string is a line of stdout from the MalwareJail tool
        :return: None
        """
        if path.exists(self.malware_jail_sandbox_env_dump_path):
            # Get the sandbox env json that is dumped. This should always exist.
            malware_jail_sandbox_env_dump = {
                "name": self.malware_jail_sandbox_env_dump,
                "path": self.malware_jail_sandbox_env_dump_path,
                "description": "Sandbox Environment Details",
                "to_be_extracted": False,
            }
            self.log.debug(f"Adding supplementary file: {self.malware_jail_sandbox_env_dump}")
            self.artifact_list.append(malware_jail_sandbox_env_dump)

        if output:
            with open(self.malware_jail_output_path, "w") as f:
                for line in output:
                    f.write(line + "\n")
            mlwr_jail_out = {
                "name": self.malware_jail_output,
                "path": self.malware_jail_output_path,
                "description": "Malware Jail Output",
                "to_be_extracted": False,
            }
            self.log.debug(f"Adding supplementary file: {self.malware_jail_output}")
            self.artifact_list.append(mlwr_jail_out)

        if len(glob(self.boxjs_analysis_log)) > 0:
            boxjs_analysis_log = max(glob(self.boxjs_analysis_log), key=path.getctime)
            boxjs_analysis_log = {
                "name": "boxjs_analysis_log.log",
                "path": boxjs_analysis_log,
                "description": f"{BOX_JS} Output",
                "to_be_extracted": False,
            }
            self.log.debug(f"Adding supplementary file: {boxjs_analysis_log}")
            self.artifact_list.append(boxjs_analysis_log)

    def _run_signatures(self, output: List[str], result: Result, display_iocs: bool = False) -> None:
        """
        This method sets up the parallelized signature engine and runs each signature against the
        stdout from MalwareJail
        :param output: A list of strings where each string is a line of stdout from the MalwareJail tool
        :param result: A Result object containing the service results
        :param display_iocs: A boolean indicating if we are going to include the signature marks in the
        ResultSection
        :return: None
        """
        # Loading signatures
        sigs = []
        abstracts = "signatures.abstracts"
        signature_class = "Signature"
        for _, modname, _ in iter_modules(signatures.__path__, f"{signatures.__name__}."):
            if modname == abstracts:
                continue
            __import__(modname)
            clsmembers = getmembers(modules[modname], isclass)
            for cls in clsmembers:
                name, obj = cls
                if name == signature_class:
                    continue
                sigs.append(obj())

        # Running signatures
        signatures_that_hit = []
        sig_threads = []

        self.log.debug(f"Running {len(sigs)} signatures...")
        start_time = time()
        for sig in sigs:
            thr = Thread(target=self._process_signature, args=(sig, output, signatures_that_hit), daemon=True)
            sig_threads.append(thr)
            thr.start()

        for thread in sig_threads:
            thread.join()
        self.log.debug(f"Completed running {len(sigs)} signatures! Time elapsed: {round(time() - start_time)}s")

        phishing_terms = False
        phishing_logos = False
        phishing_form = False

        # Adding signatures to results
        if len(signatures_that_hit) > 0:
            sigs_res_sec = ResultSection("Signatures")
            # Sort alphabetically since the results could be inconsistent otherwise if threads finish at different times
            for sig_that_hit in sorted(signatures_that_hit, key=lambda x: x.name):
                if sig_that_hit.name == "split_reverse_join":
                    self.split_reverse_join = True
                elif sig_that_hit.name == "phishing_terms":
                    phishing_terms = True
                elif sig_that_hit.name == "phishing_logo_download":
                    phishing_logos = True
                elif sig_that_hit.name == "base64_encoded_url":
                    for mark in sig_that_hit.marks:
                        uri = re.match(ATOB_URI_REGEX, mark)
                        if uri and len(uri.regs) == 2:
                            self.base64_encoded_urls.append(uri.group(1))
                elif sig_that_hit.name == "form_action_uri":
                    phishing_form = True
                elif sig_that_hit.name == "document_write":
                    self.html_document_write = True

                sig_res_sec = ResultTextSection(f"Signature: {type(sig_that_hit).__name__}", parent=sigs_res_sec)
                sig_res_sec.add_line(sig_that_hit.description)
                sig_res_sec.set_heuristic(sig_that_hit.heuristic_id)
                translated_score = TRANSLATED_SCORE[sig_that_hit.severity]
                sig_res_sec.heuristic.add_signature_id(sig_that_hit.name, score=translated_score)
                if display_iocs:
                    for mark in sig_that_hit.marks:
                        sig_res_sec.add_line(f"\t\t{truncate(mark)}")

            # Signature combos
            sig_hit_names = [sig.name for sig in signatures_that_hit]
            if all(item in sig_hit_names for item in ["save_to_file", "writes_executable", "runs_shell"]):
                self.url_used_for_suspicious_exec = True
            elif all(item in sig_hit_names for item in ["runs_ps1_to_download", "runs_shell"]):
                ps1_to_download_sig = next(
                    (sig for sig in signatures_that_hit if sig.name == "runs_ps1_to_download"), None
                )
                http_res = ResultTableSection("Suspicious URL Downloaded by PowerShell", parent=sigs_res_sec)
                for mark in ps1_to_download_sig.marks:
                    extract_iocs_from_text_blob(mark, http_res)
                if http_res.body and http_res.tags.get("network.dynamic.uri"):
                    http_res.set_heuristic(13)
                    http_res.heuristic.add_signature_id("suspicious_pwsh_url", 500)
            # These are common phishing techniques used together for obfuscation
            # Step 1: Base64 decoding
            # Step 2: DOM Write
            elif "base64_decoding" in sig_hit_names and (
                self.html_document_write and self.sample_type == "code/html" or self.gauntlet_runs > 1
            ):
                self.is_phishing = True

            result.add_section(sigs_res_sec)

        # A regular form asking for credentials is not phishing, so we need more than just
        # phishing terms + one of phishing logos and phishing form
        if (
            not self.is_phishing
            and phishing_terms
            and (phishing_logos or phishing_form)
            and len(signatures_that_hit) > 2
        ):
            self.is_phishing = True

    @staticmethod
    def _process_signature(signature: Signature, output: List[str], signatures_that_hit: List[Signature]) -> None:
        """
        This method is used for the purpose of multi-threading and sharing the signatures_that_hit list
        :param signature: A Signature object that represents a signature
        :param output: A list of strings where each string is a line of stdout from the MalwareJail tool
        :param signatures_that_hit: A list containing all signatures that hit
        :return: None
        """
        signature.process_output(output)
        if len(signature.marks) > 0:
            signatures_that_hit.append(signature)

    def _extract_boxjs_iocs(self, result: Result) -> None:
        """
        This method extracts IOCs that Box.js has reported
        :param result: A Result object containing the service results
        :return: None
        """
        self.log.debug(f"Extracting IOCs from {BOX_JS} output...")
        if len(glob(self.boxjs_iocs)) == 0:
            return

        boxjs_iocs = max(glob(self.boxjs_iocs), key=path.getctime)
        ioc_result_section = ResultSection(f"IOCs extracted by {BOX_JS}")
        with open(boxjs_iocs, "r") as f:
            file_contents = f.read()

        ioc_json: List[Dict[str, Any]] = []
        try:
            ioc_json = loads(file_contents)
        except JSONDecodeError as e:
            self.log.warning(f"Failed to json.load() {BOX_JS}'s IOC JSON due to {e}")

        batch_cmd_spotted = False
        ps1_cmd_spotted = False

        boxjs_batch_extraction = open(self.boxjs_batch_path, "a+")
        boxjs_ps1_extraction = open(self.boxjs_ps1_path, "a+")
        boxjs_batch_extraction.write(CUSTOM_BATCH_ID.decode())
        boxjs_ps1_extraction.write(CUSTOM_PS1_ID.decode())

        commands = set()
        commands_to_display = list()
        file_writes = set()
        file_reads = set()
        cmd_count = 0
        for ioc in ioc_json:
            type = ioc["type"]
            value = ioc.get("value", "")
            if type == "Run" and "command" in value:
                if value["command"] not in commands:
                    commands.add(value["command"].strip())

                # We want to extract powershell commands to a powershell file, which can be confirmed using multidecoder
                try:
                    matches = find_powershell_strings(value["command"].encode())
                except BinasciiError as e:
                    self.log.debug(f"Could not base64-decode encoded command value '{value['command']}' due to '{e}'")
                    matches = []

                if matches:
                    for match in matches:
                        powershell_command = get_powershell_command(match.value)
                        # Replace the obfuscated powershell command with the deobfuscated command
                        commands_to_display.append(powershell_command.decode().strip())
                        boxjs_ps1_extraction.write(powershell_command.decode().strip() + "\n")
                        ps1_cmd_spotted = True
                else:
                    # Write non-ps1 to file
                    commands_to_display.append(value["command"].strip())
                    boxjs_batch_extraction.write(value["command"].strip() + "\n")
                    batch_cmd_spotted = True

                cmd_count += 1
            elif type == "FileWrite" and "file" in value:
                file_writes.add(value["file"])
            elif type == "FileRead" and "file" in value:
                file_reads.add(value["file"])

        boxjs_ps1_extraction.close()
        boxjs_batch_extraction.close()

        if batch_cmd_spotted:
            artifact = {
                "name": self.boxjs_batch,
                "path": self.boxjs_batch_path,
                "description": "Boxjs batch file",
                "to_be_extracted": True,
            }
            self.log.debug(f"Adding extracted file: {self.boxjs_batch}")
            self.artifact_list.append(artifact)

        if ps1_cmd_spotted:
            artifact = {
                "name": self.boxjs_ps1,
                "path": self.boxjs_ps1_path,
                "description": "Boxjs ps1 file",
                "to_be_extracted": True,
            }
            self.log.debug(f"Adding extracted file: {self.boxjs_ps1}")
            self.artifact_list.append(artifact)

        if batch_cmd_spotted or ps1_cmd_spotted:
            cmd_result_section = ResultTextSection("The script ran the following commands", parent=ioc_result_section)
            cmd_result_section.add_lines(commands_to_display)
            [cmd_result_section.add_tag("dynamic.process.command_line", command) for command in commands_to_display]
            cmd_iocs_result_section = ResultTableSection("IOCs found in command lines")
            extract_iocs_from_text_blob(cmd_result_section.body, cmd_iocs_result_section, is_network_static=True)
            if cmd_iocs_result_section.body:
                cmd_iocs_result_section.set_heuristic(2)
                cmd_result_section.add_subsection(cmd_iocs_result_section)

        if file_writes:
            file_writes_result_section = ResultTextSection(
                "The script wrote the following files", parent=ioc_result_section
            )
            file_writes_result_section.add_lines(list(file_writes))
            [
                file_writes_result_section.add_tag("dynamic.process.file_name", file_write)
                for file_write in list(file_writes)
            ]

        if file_reads:
            file_reads_result_section = ResultTextSection(
                "The script read the following files", parent=ioc_result_section
            )
            file_reads_result_section.add_lines(list(file_reads))
            [
                file_reads_result_section.add_tag("dynamic.process.file_name", file_read)
                for file_read in list(file_reads)
            ]

        if ioc_result_section.subsections:
            ioc_result_section.set_heuristic(2)
            result.add_section(ioc_result_section)

    def _flag_jsxray_iocs(self, output: Dict[str, Any], request: ServiceRequest) -> bool:
        """
        This method flags anything noteworthy from the Js-X-Ray output
        :param output: The output from JS-X-Ray
        :param request: The ServiceRequest object
        :return: A boolean flag representing that we should run Synchrony
        """
        jsxray_iocs_result_section = ResultTextSection(f"{JS_X_RAY} IOCs Detected")
        warnings: List[Dict[str, Any]] = output.get("warnings", [])
        signature = None
        run_synchrony = False
        for warning in warnings:
            kind = warning["kind"]
            val = warning.get("value")
            if kind == "unsafe-stmt":
                jsxray_iocs_result_section.add_line(f"\t\tAn unsafe statement was found: {truncate(safe_str(val))}")
            elif kind == "encoded-literal":
                line = f"\t\tAn encoded literal was found: {truncate(safe_str(val))}"
                if (
                    not jsxray_iocs_result_section.body
                    or jsxray_iocs_result_section.body
                    and line not in jsxray_iocs_result_section.body
                ):
                    # Determine if value is hex
                    is_hex = False
                    try:
                        int(val, 16)
                        is_hex = True
                    except ValueError:
                        pass
                    if is_hex:
                        try:
                            encoded_val = val.encode()
                            # https://stackoverflow.com/questions/41264280/odd-length-string-error-with-binascii-unhexlify
                            if len(encoded_val) % 2 == 1:
                                encoded_val = b"0" + encoded_val
                            decoded_hex = hexload(encoded_val)
                        except BinasciiError:
                            decoded_hex = b""

                        if any(PE_indicator in decoded_hex for PE_indicator in PE_INDICATORS):
                            with tempfile.NamedTemporaryFile(dir=self.working_directory, delete=False) as out:
                                out.write(decoded_hex)
                            file_name = sha256(decoded_hex).hexdigest()
                            self.log.debug(f"Adding extracted PE {file_name} that was found in decoded HEX string.")
                            self.artifact_list.append(
                                {
                                    "name": file_name,
                                    "path": out.name,
                                    "description": "Extracted PE found in decoded HEX string",
                                    "to_be_extracted": True,
                                }
                            )
                            signature = "decoded_hex_pe"
                    jsxray_iocs_result_section.add_line(line)
                    jsxray_iocs_result_section.add_tag("file.string.extracted", truncate(safe_str(val)))
            elif kind == "obfuscated-code":
                jsxray_iocs_result_section.add_line(
                    f"\t\tObfuscated code was found that was obfuscated by: " f"{safe_str(val)}"
                )
                # https://github.com/NodeSecure/js-x-ray/blob/master/src/obfuscators/obfuscator-io.js
                if safe_str(val) == OBFUSCATOR_IO:
                    run_synchrony = True
            elif kind == "shady-link":
                if not is_url(val.encode()) and not is_domain(val.encode()):
                    continue
                else:
                    add_tag(jsxray_iocs_result_section, "network.static.uri", val, self.safelist)
            elif kind in ["suspicious-literal", "short-identifiers", "suspicious-file", "unsafe-regex"]:
                # We don't care about these warnings
                continue
            else:
                jsxray_iocs_result_section.add_line(f"\t\t{kind}:{val}")

        if jsxray_iocs_result_section.body and len(jsxray_iocs_result_section.body) > 0:
            jsxray_iocs_result_section.set_heuristic(2)
            if signature:
                jsxray_iocs_result_section.heuristic.add_signature_id(signature)
            request.result.add_section(jsxray_iocs_result_section)

        return run_synchrony

    def _extract_synchrony(self, request: ServiceRequest, timed_out: object):
        """
        This method extracts the created Synchrony artifact, if applicable
        :param request: The ServiceRequest object
        :return: None
        """
        # We do not want a loop of Synchrony extractions
        if request.temp_submission_data.get("cleaned_by_synchrony") and request.task.file_name.endswith(".cleaned"):
            return

        if not path.exists(self.cleaned_with_synchrony_path):
            if timed_out:
                time_out_synchrony_res = ResultTextSection(f"{SYNCHRONY} timed out deobfuscating the file")
                time_out_synchrony_res.set_heuristic(8)
                request.result.add_section(time_out_synchrony_res)
            return

        deobfuscated_with_synchrony_res = ResultTextSection(f"The file was deobfuscated/cleaned by {SYNCHRONY}")
        deobfuscated_with_synchrony_res.add_line(f"View extracted file {self.cleaned_with_synchrony} for details.")
        deobfuscated_with_synchrony_res.set_heuristic(8)
        request.result.add_section(deobfuscated_with_synchrony_res)

        artifact = {
            "name": self.cleaned_with_synchrony,
            "path": self.cleaned_with_synchrony_path,
            "description": f"File deobfuscated with {SYNCHRONY}",
            "to_be_extracted": True,
        }
        self.log.debug(f"Adding extracted file: {self.cleaned_with_synchrony}")
        self.artifact_list.append(artifact)

        # If there is a URL used in a suspicious way and the file is obfuscated with Obfuscator.io,
        # we should flag this combination with a signature that scores 500
        for result_section in request.result.sections:
            if result_section.heuristic and result_section.heuristic.heur_id == 6:
                self.log.debug(
                    "Added the obfuscator_io_url_redirect signature to the result section to score the tagged URLs"
                )
                result_section.heuristic.add_signature_id("obfuscator_io_url_redirect", 500)
            elif result_section.heuristic and result_section.heuristic.heur_id == 1:
                self.log.debug(
                    "Added the obfuscator_io_usage_url signature to the result section to score the tagged URLs"
                )
                result_section.heuristic.add_signature_id("obfuscator_io_usage_url", 500)

    def parse_msdt_powershell(self, cmd):
        import shlex

        ori_parts = shlex.split(cmd)
        parts = shlex.split(cmd.lower())

        if "/param" in parts:
            param = ori_parts[parts.index("/param") + 1]
        elif "-param" in parts:
            param = ori_parts[parts.index("-param") + 1]
        else:
            return cmd

        for element in param.split():
            if element.startswith("IT_BrowseForFile="):
                return element[17:]
        return cmd

    def _extract_malware_jail_iocs(self, output: List[str], request: ServiceRequest, original_contents: bytes) -> None:
        self.log.debug(f"Extracting IOCs from the {MALWARE_JAIL} output...")
        malware_jail_res_sec = ResultTableSection(f"{MALWARE_JAIL} extracted the following IOCs")

        for line in self._parse_malwarejail_output(output):
            split_line = line.split("] ", 1)
            if len(split_line) == 2:
                log_line = split_line[1]
            else:
                log_line = line
            if len(log_line) > 5000 and not request.deep_scan:
                log_line = truncate(log_line, 5000)

            extract_iocs_from_text_blob(
                log_line,
                malware_jail_res_sec,
                enforce_char_min=True,
                enforce_domain_char_max=True,
                is_network_static=True,
                safelist=self.safelist,
            )

            if log_line.startswith("Exception occurred in "):
                exception_lines = []
                for exception_line in log_line.split("\n"):
                    if not exception_line.strip():
                        continue
                    exception_lines.append(exception_line)
                if not exception_lines:
                    continue
                exception_blurb = "\n".join(exception_lines)
                if self.config.get("raise_malware_jail_exc", False):
                    raise Exception(f"Exception occurred in {MALWARE_JAIL}\n" + exception_blurb)
                else:
                    self.log.warning(f"Exception occurred in {MALWARE_JAIL}\n" + exception_blurb)

                # Check if there is an unexpected end of input that we could remedy
                match = re.match(INVALID_END_OF_INPUT_REGEX, exception_blurb.encode())
                if match and len(match.regs) > 1:
                    line_to_wrap = match.group(1).decode()
                    amended_content = original_contents.replace(line_to_wrap.encode(), f'"{line_to_wrap}"'.encode())

                    if original_contents != amended_content:
                        with tempfile.NamedTemporaryFile(dir=self.working_directory, delete=False) as out:
                            out.write(amended_content)
                            amended_content_path = out.name

                        self.log.debug(
                            "There was an unexpected end of input, run the gauntlet again with the amended content!"
                        )
                        self._run_the_gauntlet(
                            request, amended_content_path, amended_content, original_contents, subsequent_run=True
                        )

                # Check if there was a reference error after multiple DOM writes
                match = re.match(REFERENCE_NOT_DEFINED_REGEX, exception_blurb.encode())
                if match:
                    missing_ref = match.group(1).decode()
                    self.log.debug(f"There was a reference error when accessing '{missing_ref}'")

                    if self.script_with_source_and_no_body:
                        heur = Heuristic(16)
                        script_source_res = ResultTextSection(
                            heur.name, heuristic=heur, parent=request.result, body=heur.description
                        )
                        url_sec = ResultTableSection("Possible script sources that are required for execution")
                        for script_src in self.initial_script_sources | self.subsequent_script_sources:
                            if add_tag(url_sec, "network.dynamic.uri", script_src, self.safelist):
                                url_sec.add_row(TableRow(**{"url": script_src}))

                        if url_sec.body:
                            script_source_res.add_subsection(url_sec)

            if any(log_line.startswith(item) for item in ["location.href = ", "location.replace(", "location.assign("]):
                # If the sandbox_dump.json file was not created for some reason, pull the location.href out
                # (it may be truncated, but desperate times call for desperate measures)
                location_href = ""
                if not path.exists(self.malware_jail_sandbox_env_dump_path):
                    matches = list(set([url.value.decode() for url in find_urls(log_line.encode())]))
                    if matches and len(matches) == 2:
                        location_href = matches[1]
                else:
                    # We need to recover the non-truncated content from the sandbox_dump.json file
                    with open(self.malware_jail_sandbox_env_dump_path, "r") as f:
                        data = load(f)
                        location_pointer = data["Location"]
                        if "$ref" in location_pointer:
                            location_pointer = location_pointer["$ref"]
                            # Let's clean this up so that we can access the correct reference
                            # Could look like this "$[\"ret\"][\"contentDocument\"][\"_parentNode\"][\"_location\"]"
                            if location_pointer.startswith("$"):
                                location_pointer = location_pointer[1:]

                            if location_pointer.startswith('["') and location_pointer.endswith('"]'):
                                location_pointer = location_pointer[2:-2]

                            if '"]["' in location_pointer:
                                location_pointer = location_pointer.split('"]["')

                            if not isinstance(location_pointer, list):
                                location_pointer = [location_pointer]

                            for key in location_pointer:
                                if key not in data:
                                    self.log.debug("There is an error in accessing referenced objects!")
                                    return
                                data = data[key]

                            location_href = data["_props"]["href"]
                        else:
                            location_href = location_pointer["_props"].get("href")

                # It is possible for the location_href to be assigned an empty dictionary by MalwareJail, or to be unset
                if not location_href:
                    continue
                # It is possible that window.location=window.location, so this href could be reference to itself.
                elif isinstance(location_href, dict):
                    continue

                self._handle_location_redirection(location_href, request)

            # Check if programatically created script with src set is found
            if HTMLELEMENT_SRC_SET_TO_URI in log_line and any(
                item in log_line for item in [HTMLSCRIPTELEMENT, HTMLIFRAMEELEMENT]
            ):
                uri_match = re.search(HTMLELEMENT_SRC_REGEX, log_line, re.IGNORECASE)
                if uri_match and len(uri_match.regs) == 2:
                    uri_src = uri_match.group(1)
                else:
                    continue
                if uri_src not in self.initial_script_sources:
                    self.subsequent_script_sources.add(uri_src)

        if malware_jail_res_sec.body:
            malware_jail_res_sec.set_heuristic(2)
            request.result.add_section(malware_jail_res_sec)

    def _handle_location_redirection(self, location_href: str, request: ServiceRequest):
        """
        If a location redirection related to MS-MSDT is seen, handle
        If a generic location redirection is seen, handle
        :param location_href: The URI that the page is being redirected to
        :param request: The ServiceRequest object
        """
        redirection_res_sec: Optional[ResultTextSection] = next(
            (res for res in request.result.sections if res.heuristic and res.heuristic.heur_id == 6), None
        )

        if location_href.lower().startswith("ms-msdt:"):
            heur = Heuristic(5)
            redirection_res_sec = ResultTextSection(heur.name, heuristic=heur, parent=request.result)

            # Try to only recover the msdt command's powershell for the extracted file
            # If we can't, write the whole command
            try:
                encoded_content = self.parse_msdt_powershell(location_href).encode()
            except ValueError:
                encoded_content = location_href.encode()

            with tempfile.NamedTemporaryFile(dir=self.working_directory, delete=False) as out:
                out.write(encoded_content)
            artifact = {
                "name": sha256(encoded_content).hexdigest(),
                "path": out.name,
                "description": "Redirection location",
                "to_be_extracted": True,
            }
            self.log.debug(f"Redirection location: {out.name}")
            self.artifact_list.append(artifact)
        elif not redirection_res_sec:
            heur = Heuristic(6)
            redirection_res_sec = ResultTextSection(heur.name, heuristic=heur, parent=request.result)

        if not redirection_res_sec.body or (
            redirection_res_sec.body and f"Redirection to:\n{location_href}" not in redirection_res_sec.body
        ):
            if add_tag(redirection_res_sec, "network.static.uri", location_href, self.safelist):
                redirection_res_sec.add_line(f"Redirection to:\n{location_href}")

                if any(urlparse(decoded_url).netloc in location_href for decoded_url in self.base64_encoded_urls):
                    redirection_res_sec.heuristic.add_signature_id("redirection_to_base64_decoded_url", 500)

    def _handle_subsequent_scripts(self, result: Result):
        """
        This method handles subsequent script sources, by creating a result section and applying applicable signatures
        :param result: A Result object containing the service results
        :return: None
        """
        if not self.subsequent_script_sources:
            return

        heur = Heuristic(18)
        dynamic_script_source_res = ResultTableSection(heur.name, heuristic=heur)
        # Check if domain or IP matches that of a URI that is programmatically loaded
        for script_src in sorted(list(self.subsequent_script_sources)):
            if add_tag(dynamic_script_source_res, "network.dynamic.uri", script_src, self.safelist):
                if any(urlparse(decoded_url).netloc in script_src for decoded_url in self.base64_encoded_urls):
                    # This is suspicious, flag it!
                    dynamic_script_source_res.heuristic.add_signature_id(
                        "programmatically_created_base64_decoded_url", 500
                    )
                dynamic_script_source_res.add_row(TableRow(**{"url": script_src}))

        if self.gauntlet_runs >= 5:
            # It is common-place to write scripts to the DOM for some reason, so we'll only score URLs after
            # 5 runs fo the gauntlet
            dynamic_script_source_res.heuristic.add_signature_id("multi_write_3rd_party_script", 500)

        if dynamic_script_source_res.body:
            result.add_section(dynamic_script_source_res)

    def _run_tool(
        self,
        tool_name: str,
        args: List[str],
        resp: Dict[str, Any],
    ) -> None:
        """
        This method runs a tool and appends the stdout from that tool to the dictionary
        :param tool_name: The name of the tool to be run
        :param args: A list of arguments to use to run the tool
        :param resp: A dictionary used to contain the stdout from a tool
        :return: None
        """
        # We are on a second attempt here
        if resp.get(tool_name, []) == [EXITED_DUE_TO_STDOUT_LIMIT]:
            do_not_terminate = True
        else:
            do_not_terminate = False

        self.log.debug(f"Running {tool_name}...")
        start_time = time()
        resp[tool_name] = []
        try:
            # Stream stdout to resp rather than waiting for process to finish
            with Popen(
                args=args,
                stdout=PIPE,
                stderr=PIPE if self.config.get("send_tool_stderr_to_pipe", False) else None,
                bufsize=1,
                universal_newlines=True,
            ) as p:
                for line in p.stdout:
                    resp[tool_name].append(line)
                    # If we are keeping to the stdout limit, then do so
                    if not self.ignore_stdout_limit and len(resp[tool_name]) > self.stdout_limit:
                        stdout_limit_reached_time = round(time() - start_time)
                        self.log.warning(
                            f"{tool_name} generated more than {self.stdout_limit} lines of output. \
                            Time elapsed: {stdout_limit_reached_time}s"
                        )
                        if not do_not_terminate:
                            p.terminate()
                            resp[tool_name].append(EXITED_DUE_TO_STDOUT_LIMIT)
                            resp[tool_name].append(stdout_limit_reached_time)
                        return
        except TimeoutExpired:
            pass
        except Exception as e:
            self.log.warning(f"{tool_name} crashed due to {repr(e)}")
        self.log.debug(f"Completed running {tool_name}! Time elapsed: {round(time() - start_time)}s")

    def _extract_filtered_code(self, file_contents: bytes) -> Tuple[Optional[str], Optional[bytes], Optional[str]]:
        file_contents = file_contents.decode()
        common_libs = {
            # URL/FILE: REGEX
            "https://code.jquery.com/jquery-%s.js": JQUERY_VERSION_REGEX,
            "tools/gootloader/clean_libs/maplace%s.js": MAPLACE_REGEX,
            "tools/gootloader/clean_libs/combo.js": COMBO_REGEX,
            "tools/gootloader/clean_libs/underscore%s.js": UNDERSCORE_REGEX,
            "tools/gootloader/clean_libs/d3_v%s.js": D3_REGEX,
            "tools/gootloader/clean_libs/lodash%s.js": LODASH_REGEX,
            "tools/gootloader/clean_libs/chartview.js": CHARTVIEW_REGEX,
            "tools/gootloader/clean_libs/mdl.js": MDL_REGEX,
        }
        file_contents = file_contents.replace("\r", "")
        split_file_contents = [line.strip() for line in file_contents.split("\n") if line.strip()]
        for lib_path, regex in common_libs.items():
            regex_match = re.match(regex, file_contents)
            if not regex_match:
                continue
            path_contents = None
            if lib_path.startswith("https"):
                if not self.service_attributes.docker_config.allow_internet_access:
                    continue
                if len(regex_match.regs) > 1:
                    lib_path = lib_path % regex_match.group(1)
                    resp = get(lib_path, timeout=15)
                else:
                    resp = get(lib_path, timeout=15)

                path_contents = resp.text
            else:
                if len(regex_match.regs) > 1:
                    lib_path = lib_path % regex_match.group(1)

                if path.exists(lib_path):
                    path_contents = open(lib_path, "r").read()
                else:
                    self.log.warning(
                        f"There was a regex hit for a clean library file '{lib_path}' but this "
                        "file does not exist..."
                    )

            if not path_contents:
                continue

            diff = list()
            clean_file_contents = [line.strip() for line in path_contents.split("\n") if line.strip()]
            # The dirty file contents should always have more lines than the clean file contents
            dirty_file_line_offset = 0
            for index, item in enumerate(clean_file_contents):
                dirty_file_line_index = index + dirty_file_line_offset

                if dirty_file_line_index >= len(split_file_contents):
                    break

                dirty_file_line_to_compare = split_file_contents[dirty_file_line_index]
                if self._compare_lines(item, dirty_file_line_to_compare):
                    pass
                # Python has difficulty with decoding .. and ..., so skip it!
                # (the malicious lines are not in the clean files anyways)
                elif ".." in item:
                    continue
                else:
                    while not self._compare_lines(item, dirty_file_line_to_compare):
                        diff.append(dirty_file_line_to_compare)
                        dirty_file_line_offset += 1
                        dirty_file_line_index = index + dirty_file_line_offset

                        if dirty_file_line_index >= len(split_file_contents):
                            break

                        dirty_file_line_to_compare = split_file_contents[dirty_file_line_index]

            if len(diff) > 10:
                new_file_contents = b""
                for line in diff:
                    new_file_contents += f"{line}\n".encode()
                with tempfile.NamedTemporaryFile(dir=self.working_directory, delete=False, mode="wb") as f:
                    f.write(new_file_contents)
                    file_path = f.name
                return file_path, new_file_contents, lib_path

        return None, None, None

    @staticmethod
    def _compare_lines(line_1: str, line_2: str) -> bool:
        """
        This method compares two lines and returns their equivalence
        :param line_1: The first line to compare
        :param line_2: The second line to compare
        :return: A boolean representing that the lines are equivalent
        """
        if line_1.startswith("//"):
            line_1 = line_1[2:]

        if line_2.startswith("//"):
            line_2 = line_2[2:]

        line_1 = line_1.strip()
        line_2 = line_2.strip()

        return line_1 == line_2

    def _convert_vb_static_variables(
        self, body: str, js_content: bytes, aggregated_js_script: Optional[tempfile.NamedTemporaryFile]
    ) -> Tuple[bytes, tempfile.NamedTemporaryFile]:
        """
        This method looks in VisualBasic scripts for variable declaration, and converts them to JavaScript
        :param body: The VisualBasic script body to be looked through
        :param file_content: The file content of the NamedTemporaryFile
        :param aggregated_js_script: The NamedTemporaryFile object
        :return: A tuple of the file contents of the NamedTemporaryFile object and the NamedTemporaryFile object
        """
        static_vars = re.findall(VBS_GRAB_VARS_REGEX, body, re.IGNORECASE)
        if static_vars:
            vbscript_conversion = ""
            for variable_declaration in static_vars:
                if len(variable_declaration) == 2:
                    variable_name, variable_value = variable_declaration
                    if "\\" in variable_value:
                        variable_value = variable_value.replace("\\", "\\\\")
                    vbscript_conversion += f"var {variable_name} = {variable_value};\n"

            if vbscript_conversion:
                js_content, aggregated_js_script = self.append_content(
                    vbscript_conversion, js_content, aggregated_js_script
                )
        return js_content, aggregated_js_script

    def _convert_vb_wscript_shell_declaration(
        self, body: str, js_content: bytes, aggregated_js_script: Optional[tempfile.NamedTemporaryFile]
    ) -> Tuple[Optional[str], bytes, tempfile.NamedTemporaryFile]:
        """
        This method looks in VisualBasic scripts for a WScript.Shell declaration, and converts it to JavaScript
        :param body: The VisualBasic script body to be looked through
        :param file_content: The file content of the NamedTemporaryFile
        :param aggregated_js_script: The NamedTemporaryFile object
        :return: A tuple of the variable name of the declared WScript.Shell, file contents of the
                 NamedTemporaryFile object and the NamedTemporaryFile object
        """
        wscript_varname = None
        wscript_name = re.search(VBS_WSCRIPT_SHELL_REGEX, body, re.IGNORECASE)
        if wscript_name and len(wscript_name.regs) > 1:
            wscript_varname = wscript_name.group("varname")

            if wscript_varname == WSHSHELL:
                wscript_varname = wscript_varname.lower()

            vbscript_conversion = f"var {wscript_varname} = new ActiveXObject('WScript.Shell');"

            js_content, aggregated_js_script = self.append_content(
                vbscript_conversion, js_content, aggregated_js_script
            )

        return wscript_varname, js_content, aggregated_js_script

    def _convert_vb_regwrite(
        self,
        wscript_varname: str,
        body: str,
        js_content: bytes,
        aggregated_js_script: Optional[tempfile.NamedTemporaryFile],
    ) -> Tuple[bytes, tempfile.NamedTemporaryFile]:
        """
        This method looks in VisualBasic scripts for RegWrite usage with the previously created WScript.Shell variable,
        and converts it to JavaScript
        :param wscript_varname: The variable name of the declared WScript.Shell
        :param body: The VisualBasic script body to be looked through
        :param js_content: The file content of the NamedTemporaryFile
        :param aggregated_js_script: The NamedTemporaryFile object
        :return: A tuple of the file contents of the NamedTemporaryFile object and the NamedTemporaryFile object
        """
        regwrite = re.search(VBS_WSCRIPT_REG_WRITE_REGEX % wscript_varname, body, re.IGNORECASE)
        if regwrite and len(regwrite.regs) > 3:
            key_varname = regwrite.group("key")

            # Preserve escaped backslashes in the new file
            if "\\" in key_varname:
                key_varname = key_varname.replace("\\", "\\\\")

            content_varname = regwrite.group("content")
            type_varname = regwrite.group("type")
            vbscript_conversion = f"{wscript_varname}.RegWrite({key_varname}, {content_varname}, {type_varname});\n"

            js_content, aggregated_js_script = self.append_content(
                vbscript_conversion, js_content, aggregated_js_script
            )

        return js_content, aggregated_js_script

    def _find_js_function_declaration(self, body: str) -> Optional[str]:
        """
        This method looks in JavaScript scripts for a new Function being declared,
        and possibly reassigned to another variable
        :param body: The JavaScript script body to be looked through
        :return: The name of the variable pointing at the new Function
        """
        function_varname = None
        new_fn = re.search(JS_NEW_FUNCTION_REGEX, body, re.IGNORECASE)
        if new_fn and len(new_fn.regs) > 3:
            function_varname = new_fn.group("function_varname")

            # Check for reassignment
            fn_reassignment = re.search(JS_NEW_FUNCTION_REASSIGN_REGEX % function_varname, body, re.IGNORECASE)
            if fn_reassignment and len(fn_reassignment.regs) > 1:
                function_varname = fn_reassignment.group("new_name")
        return function_varname

    def _look_for_iocs_between_vb_and_js(
        self, body: str, vb_and_js_section: ResultTextSection, url_sec: Optional[ResultTableSection] = None
    ) -> Optional[ResultTableSection]:
        """
        This method looks for network IOCs (specifically URIs) being used in script bodies
        :param body: The script body to be looked through
        :param vb_and_js_section: The ResultSection that will contain the subsection detailing the IOCs + heuristic +
                                  signature
        :return: The URL section that may have been added to the vb_and_js_section
        """
        if not vb_and_js_section:
            return

        previous_url_sec = url_sec is not None

        # If we did not receive a previous url_sec...
        if not previous_url_sec:
            url_sec = ResultTableSection("IOCs found being passed between Visual Basic and JavaScript")

        extract_iocs_from_text_blob(body, url_sec, is_network_static=True)

        # Perform the following only if this is the first time we are seeing a url_sec
        if url_sec.body and url_sec.tags.get("network.static.uri"):
            if not previous_url_sec:
                # Move heuristic to this IOC section so that the score is associated with the tag
                url_sec.set_heuristic(12)
                vb_and_js_section.set_heuristic(None)
                vb_and_js_section.add_subsection(url_sec)
                url_sec.heuristic.add_signature_id("suspicious_url_found", 500)
            # Once we have url_sec that has tags, we always return it
            return url_sec
        else:
            return None

    def _convert_vb_function_call(
        self,
        function_varname: str,
        body: str,
        vb_and_js_section: ResultTextSection,
        js_content: bytes,
        aggregated_js_script: Optional[tempfile.NamedTemporaryFile],
    ) -> Tuple[bytes, tempfile.NamedTemporaryFile]:
        """
        This method looks in VisualBasic scripts for Function calls where the Function was
        declared in a previous JavaScript script (see _find_js_function_declaration)
        :param function_varname: The name of the variable pointing at the new Function
        :param body: The JavaScript script body to be looked through
        :param vb_and_js_section: The ResultSection that will contain the subsection detailing the IOCs + heuristic +
                                  signature for URIs
        :param file_content: The file content of the NamedTemporaryFile
        :param aggregated_js_script: The NamedTemporaryFile object
        :return: A tuple of the file contents of the NamedTemporaryFile object and the NamedTemporaryFile object
        """
        function_call = re.search(VBS_FUNCTION_CALL % function_varname, body, re.IGNORECASE)

        if function_call and len(function_call.regs) > 1:
            self._look_for_iocs_between_vb_and_js(body, vb_and_js_section)

            func_args = function_call.group("func_args")
            vbscript_fn_conversion = f"{function_varname}({func_args})\n"
            js_content, aggregated_js_script = self.append_content(
                vbscript_fn_conversion, js_content, aggregated_js_script
            )

        return js_content, aggregated_js_script

    def _hunt_for_suspicious_titles(self, soup: BeautifulSoup) -> None:
        """
        This method looks for possible "titles" of the webpage, and then hunts for
        commonly used terms found in phishing.
        :param soup: The BeautifulSoup object
        :return: None
        """
        # First let's look for the actual titles
        # https://developer.mozilla.org/en-US/docs/Web/HTML/Element/title
        # https://beautiful-soup.readthedocs.io/en/latest/#string
        titles = [title.string.strip() for title in soup.findAll("title") if title.string and title.string.strip()]

        # Now we'll look for visible text
        # https://beautiful-soup.readthedocs.io/en/latest/#get-text
        potential_titles = [item.strip() for item in soup.get_text().split("\n") if item.strip()]
        if potential_titles:
            titles.extend(potential_titles)

        for title in titles:
            # Phishing titles are not long
            if len(title) > 100:
                continue
            # Do not start with tags
            elif title.startswith("<") and title.endswith(">"):
                continue
            # Are not CSS
            elif title.startswith("/*") and title.endswith("*/") or title.startswith("."):
                continue

            # Let's start the threshold with two or more phishing terms in the title
            hits = re.findall(PHISHING_TITLE_TERMS_REGEX, title, re.IGNORECASE)
            # Also, look for passwords
            hits.extend([item for item in PASSWORD_WORDS if item.lower() in title.lower()])
            if len(hits) >= 2:
                self.html_phishing_title.add(title)

    def _hunt_for_suspicious_input_fields(self, soup: BeautifulSoup) -> None:
        """
        This method looks for input fields and then tries to determine if these fields are used for sensitive user data.
        :param soup: The BeautifulSoup object
        :return: None
        """
        # First get all of the inputs
        inputs = [inp for inp in soup.findAll("input")]

        if not inputs:
            return

        for inp in inputs:
            inp_hits = []
            # Now look through the attributes to find any pertaining to sensitive user data
            for key, value in inp.attrs.items():
                if not value:
                    continue
                # These are the attributes we care about
                if key not in ["name", "id", "placeholder", "value", "type"]:
                    continue
                inp_hits.extend([item for item in PHISHING_INPUTS + PASSWORD_WORDS if item.lower() in value.lower()])
            if inp_hits:
                self.phishing_inputs.add(
                    f"<input> element '{inp.attrs.get('id', 'unknown_id')}' "
                    f"contains the following phishing terms: '{', '.join(sorted(set(inp_hits)))}'"
                )

    def _hunt_for_suspicious_forms(self, soup: BeautifulSoup) -> None:
        """
        This method looks for password input fields as well as forms with no actions, which is suspicious.
        :param soup: The BeautifulSoup object
        :return: None
        """
        # First get all of the inputs
        # Note that it is not as simple as just looking for all inputs with the type="password"
        inputs = [inp for inp in soup.findAll("input")]

        if not inputs:
            return

        password_field_exists = False
        for inp in inputs:
            # Now look through the attributes to find any pertaining to sensitive user data
            for key, value in inp.attrs.items():
                if not value:
                    continue
                # These are the attributes we care about
                if key not in ["name", "id", "placeholder", "value", "type"]:
                    continue
                if any(item.lower() in value.lower() for item in PASSWORD_WORDS):
                    # Yay we have a password field!
                    password_field_exists = True
                    break

            if password_field_exists:
                break

        if password_field_exists:
            # Inspired by https://github.com/sandialabs/laikaboss/blob/8dd2ca17c18d4d0d363d566798720acb7b4d3662/laikaboss/modules/scan_html.py#L375
            if len(inputs) > 0 and len(inputs) < 4:
                self.short_form = True

            # If we have a password field, let's look at the form details
            # https://developer.mozilla.org/en-US/docs/Web/HTML/Element/form
            forms = soup.findAll("form")
            if not forms:
                return
            for form in forms:
                form_has_action = False
                for key, value in form.attrs.items():
                    if not value:
                        continue
                    # https://developer.mozilla.org/en-US/docs/Web/HTML/Element/form#attributes_for_form_submission
                    if key == "action" and is_url(value.encode()):
                        form_has_action = True
                        if self.single_script_with_unescape:
                            # A form with an action was created from a single script that used an unescape AND the form
                            # contains a password input field
                            self.sus_form_actions.add(value)
                        elif self.html_phishing_title and self.phishing_inputs:
                            # We have a suspicious doc title and inputs, plus we have a form that submits? That's enough
                            self.sus_form_actions.add(value)
                        break

                if form_has_action:
                    break

                # The form action can be overridden, so we need to look at a few more items
                else:
                    for form_child in form.children:
                        if (
                            form_child.name == "button"
                            or form_child.name == "input"
                            and form_child.attrs.get("type") in ["submit", "image"]
                        ):
                            # Potential
                            for key, value in form.attrs.items():
                                if not value:
                                    continue
                                # https://developer.mozilla.org/en-US/docs/Web/HTML/Element/form#action
                                if key == "formaction" and is_url(value.encode()):
                                    form_has_action = True
                                    if self.single_script_with_unescape:
                                        # A form with an action was created from a single script that used an
                                        # unescape AND the form contains a password input field
                                        self.sus_form_actions.add(value)
                                    elif self.html_phishing_title and self.phishing_inputs:
                                        self.sus_form_actions.add(value)
                                    break

                            if form_has_action:
                                break

                if not form_has_action:
                    self.password_input_and_no_form_action = True

    def _hunt_for_suspicious_meta(self, soup: BeautifulSoup, request: ServiceRequest) -> None:
        """
        This method looks for meta redirects, which are suspicious.
        Inspired by https://github.com/sandialabs/laikaboss/blob/8dd2ca17c18d4d0d363d566798720acb7b4d3662/laikaboss/modules/scan_html.py#L264
        :param soup: The BeautifulSoup object
        :param request: The ServiceRequest object
        :return: None
        """
        # https://developer.mozilla.org/en-US/docs/Web/HTML/Element/meta
        metas = soup.findAll("meta")

        for meta in metas:
            # Metadata equivalent to http headers
            # https://developer.mozilla.org/en-US/docs/Web/HTML/Element/meta#http-equiv
            if meta.has_attr("http-equiv"):
                if meta.get("http-equiv").lower() == "refresh":
                    url_data = meta.get("content", "unknown")
                    urls = list(set([url.value.decode() for url in find_urls(url_data.encode())]))
                    if urls:
                        self._handle_location_redirection(urls[0], request)

    def _hunt_for_suspicious_images(self, soup: BeautifulSoup):
        """
        This method looks for web bugs, which are suspicious.
        Web bug/beacon: https://en.wikipedia.org/wiki/Web_beacon
        Inspired by https://github.com/sandialabs/laikaboss/blob/8dd2ca17c18d4d0d363d566798720acb7b4d3662/laikaboss/modules/scan_html.py#L304
        :param soup: The BeautifulSoup object
        :return: None
        """
        imgs = soup.findAll("img")

        for img in imgs:
            d = {}
            try:
                if img.has_attr("height"):
                    try:
                        d["height"] = int(img.get("height"))
                    except Exception:
                        try:
                            d["height"] = img.get("height")
                            if isinstance(d["height"], str):
                                d["height"] = d["height"].encode("utf-8")
                        except Exception:
                            pass
                if img.has_attr("width"):
                    try:
                        d["width"] = int(img.get("width"))
                    except Exception:
                        try:
                            d["width"] = img.get("width")
                            if isinstance(type(d["width"]), str):
                                d["width"] = d["width"].encode("utf-8")
                        except Exception:
                            pass
                if "height" in d and "width" in d:
                    if isinstance(d["height"], int) and isinstance(d["width"], int):
                        if d["height"] <= 1 and d["width"] <= 1:
                            self.num_of_web_bugs += 1
            except Exception:
                # We don't care that much
                pass
