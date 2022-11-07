import functools

from tinycss2.ast import (
    AtKeywordToken, AtRule, Comment, CurlyBracketsBlock, Declaration,
    DimensionToken, FunctionBlock, HashToken, IdentToken, LiteralToken,
    NumberToken, ParenthesesBlock, ParseError, PercentageToken, QualifiedRule,
    SquareBracketsBlock, StringToken, UnicodeRangeToken, URLToken,
    WhitespaceToken)

from tinycss2.color3 import RGBA

from webencodings import Encoding

SKIP_COMMENTS = False
SKIP_WHITESPACE = False


def parse_declaration_list(tokens, skip_comments=False, skip_whitespace=False):
    """
    This method is the entry point to parsing the declaration list
    """
    global SKIP_WHITESPACE
    global SKIP_COMMENTS

    if skip_comments:
        SKIP_COMMENTS = True
    if skip_whitespace:
        SKIP_WHITESPACE = True
    result = []
    for token in tokens:
        if token.type == 'whitespace':
            if not SKIP_WHITESPACE:
                result.append(token)
        elif token.type == 'comment':
            if not SKIP_COMMENTS:
                result.append(token)
        elif token.type == 'at-keyword':
            # result.append(_consume_at_rule(token, tokens))
            print("At-rule spotted!")
        elif token.type == 'ident':
            declaration = _consume_declaration_in_list(token, tokens[tokens.index(token):])
            if declaration:
                declaration_as_json = to_json(declaration)
                result.append(declaration_as_json)
    return result


def _consume_declaration_in_list(first_token, tokens):
    """Like :func:`_parse_declaration`, but stop at the first ``;``."""
    other_declaration_tokens = []
    for token in tokens:
        if token == first_token:
            continue
        elif token.type == 'whitespace' and SKIP_WHITESPACE:
            continue
        elif token.type == 'comment' and SKIP_COMMENTS:
            continue
        elif token == ';':
            break
        other_declaration_tokens.append(token)
    return _parse_declaration(first_token, iter(other_declaration_tokens))


def _parse_declaration(first_token, tokens):
    """Parse a declaration.

    Consume :obj:`tokens` until the end of the declaration or the first error.

    :type first_token: :term:`component value`
    :param first_token: The first component value of the rule.
    :type tokens: :term:`iterator`
    :param tokens: An iterator yielding :term:`component values`.
    :returns:
        A :class:`~tinycss2.ast.Declaration`
        or :class:`~tinycss2.ast.ParseError`.

    """
    name = first_token
    if name.type != 'ident':
        return
        # return ParseError(name.source_line, name.source_column, 'invalid',
        #                   'Expected <ident> for declaration name, got %s.'
        #                   % name.type)

    colon = _next_significant(tokens)
    if colon is None:
        return
        # return ParseError(name.source_line, name.source_column, 'invalid',
        #                   "Expected ':' after declaration name, got EOF")
    elif colon != ':':
        return
        # return ParseError(colon.source_line, colon.source_column, 'invalid',
        #                   "Expected ':' after declaration name, got %s."
        #                   % colon.type)

    value = []
    state = 'value'
    for i, token in enumerate(tokens):
        if state == 'value' and token == '!':
            state = 'bang'
            bang_position = i
        elif state == 'bang' and token.type == 'ident' \
                and token.lower_value == 'important':
            state = 'important'
        elif token.type not in ('whitespace', 'comment'):
            state = 'value'
        value.append(token)

    if state == 'important':
        del value[bang_position:]

    return Declaration(name.source_line, name.source_column, name.value,
                       name.lower_value, value, state == 'important')


def _next_significant(tokens):
    """Return the next significant (neither whitespace or comment) token.

    :type tokens: :term:`iterator`
    :param tokens: An iterator yielding :term:`component values`.
    :returns: A :term:`component value`, or :obj:`None`.

    """
    for token in tokens:
        if token.type not in ('whitespace', 'comment'):
            return token


def significant_tokens(tokens):
    return [token for token in tokens if token.type not in ('whitespace', 'comment')]


def _generic(func):
    implementations = func()

    @functools.wraps(func)
    def run(value):
        repr(value)  # Test that this does not raise.
        return implementations[type(value)](value)
    return run


@_generic
def to_json():
    def numeric(t):
        return [
            t.representation, t.value,
            'integer' if t.int_value is not None else 'number']
    return {
        type(None): lambda _: None,
        str: lambda s: s,
        int: lambda s: s,
        list: lambda l: [to_json(el) for el in l],
        set: lambda l: [to_json(el) for el in l],
        tuple: lambda l: [to_json(el) for el in l],
        Encoding: lambda e: e.name,
        ParseError: lambda e: ['error', e.kind],

        Comment: lambda t: '/* … */',
        WhitespaceToken: lambda t: ' ',
        LiteralToken: lambda t: t.value,
        IdentToken: lambda t: t.value,
        AtKeywordToken: lambda t: {'at-keyword', t.value},
        HashToken: lambda t: {
            'hash': t.value,
            'id': t.is_identifier if t.is_identifier else 'unrestricted'
        },
        StringToken: lambda t: {'string', t.value},
        URLToken: lambda t: {'url': t.value},
        NumberToken: lambda t: ['number'] + numeric(t),
        PercentageToken: lambda t: ['percentage'] + numeric(t),
        DimensionToken: lambda t: ['dimension'] + numeric(t) + [t.unit],
        UnicodeRangeToken: lambda t: ['unicode-range', t.start, t.end],

        CurlyBracketsBlock: lambda t: ['{}'] + to_json(t.content),
        SquareBracketsBlock: lambda t: ['[]'] + to_json(t.content),
        ParenthesesBlock: lambda t: ['()'] + to_json(t.content),
        FunctionBlock: lambda t: ['function', t.name] + to_json(t.arguments),

        Declaration: lambda d: {
            d.name: {
                'values': to_json(d.value),
                'important': d.important
            }
        },
        AtRule: lambda r: ['at-rule', r.at_keyword, to_json(r.prelude),
                           to_json(r.content)],
        QualifiedRule: lambda r: {
            'type': 'qualified rule',
            'prelude': to_json(r.prelude),
            'content': to_json(r.content)
        },

        RGBA: lambda v: [round(c, 10) for c in v],
    }
