"""Tests for JsJaws regexes, helper functions, etc."""

import re

import pytest

from jsjaws import JQUERY_VERSION_REGEX


@pytest.mark.parametrize(
    ("header", "version"),
    [
        ("", None),
        ("/*!\n * jQuery JavaScript Library v1.5\n", "1.5"),
        ("/*!\n * jQuery JavaScript Library v3.7.1\n", "3.7.1"),
        ("/*!\n * jQuery JavaScript Library v3.0.0-alpha1\n", "3.0.0-alpha1"),
    ],
)
def test_JQUERY_VERSION_REGEX(header: str, version: str | None):
    match = re.match(JQUERY_VERSION_REGEX, header)
    if match is None:
        assert version is None
    else:
        assert match.group(1) == version
