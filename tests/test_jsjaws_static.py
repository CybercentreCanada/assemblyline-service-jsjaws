"""Tests for JsJaws regexes, helper functions, etc."""

from __future__ import annotations

import re

import pytest
from bs4 import Tag

from jsjaws import JQUERY_VERSION_REGEX, is_js_script, is_vb_script


@pytest.mark.parametrize(
    ("header", "version"),
    [
        ("", None),
        ("/*!\n * jQuery JavaScript Library v1.5\n", "1.5"),
        ("/*!\n * jQuery JavaScript Library v3.7.1\n", "3.7.1"),
        ("/*!\n * jQuery JavaScript Library v3.0.0-alpha1\n", "3.0.0-alpha1"),
        ("/*!\n * jQuery JavaScript Library v4.0.0-beta.2\n", "4.0.0-beta.2"),
        ("/*!\n * jQuery Compat JavaScript Library v3.0.0-alpha1\n", "compat-3.0.0-alpha1"),
    ],
)
def test_JQUERY_VERSION_REGEX(header: str, version: str | None):
    match = re.match(JQUERY_VERSION_REGEX, header)
    if match is None:
        assert version is None
    else:
        v = match.group(2)
        if match.group(1):
            v = "compat-" + v
        assert v == version


@pytest.mark.parametrize(
    ("script", "value"),
    [
        (Tag(name="script"), True),
        (Tag(name="script", attrs={"type": ""}), True),
        (Tag(name="script", attrs={"type": "text/javascript"}), True),
        (Tag(name="script", attrs={"type": "text/jscript"}), True),
        (Tag(name="script", attrs={"type": "text/javascript"}), True),
        (Tag(name="script", attrs={"language": "VBScript", "type": ""}), True),
        (Tag(name="script", attrs={"language": "VBScript"}), False),
        (Tag(name="script", attrs={"type": "text/vbscript"}), False),
        (Tag(name="script", attrs={"language": "Javascript"}), True),
    ],
)
def test_is_js_script(script, value):
    assert is_js_script(script) == value


@pytest.mark.parametrize(
    ("script", "value"),
    [
        (Tag(name="script"), False),
        (Tag(name="script", attrs={"type": "text/vbscript"}), True),
        (Tag(name="script", attrs={"language": "VBScript"}), True),
        (Tag(name="script", attrs={"language": "VBScript", "type": ""}), False),
        (Tag(name="script", attrs={"type": "text/javascript"}), False),
        (Tag(name="script", attrs={"language": "Javascript"}), False),
    ],
)
def test_is_vb_script(script, value):
    assert is_vb_script(script) == value
