from logging import Logger
from typing import Optional

from tools.gootloader.GootLoaderAutoJsDecode import gootDecode
from tools.gootloader.utils import GootLoaderConfig


class DownloadLinksNotExtracted(Exception):
    pass


def validate_extraction(final_code: str) -> bool:
    final_code = final_code.lower()
    common_final_strings = [
        "wscript",
        "substr",
        "function",
        "while",
        "new-object",
        "system.io.compression.gzipstream",
        "get-random",
        "catch{}",
        "create-object",
        "wscript.createobject",
        "wscript-sleep",
        "wscript-quit",
        "else",
        "if",
        "expandenvironmentstrings",
        "== 200",
    ]
    common_count = 0
    for common_string in common_final_strings:
        if common_string in final_code:
            common_count += 1
    return common_count >= 2


def run(
    js_file_path: str, unsafe_uris: bool = False, payload_path: str = None, stage2_path: str = None, log: Logger = print
) -> Optional[GootLoaderConfig]:
    urls: str = ""
    code: str = ""
    third_generation: bool = False
    try:
        next_stage, urls, code = gootDecode(js_file_path, unsafe_uris, payload_path, stage2_path, log)
        if not urls:
            third_generation = True
            _, urls, code = gootDecode(next_stage, unsafe_uris, payload_path, stage2_path, log)

    except Exception as e:
        log(f"Error when running GootLoaderAutoJsDecode due to {e}")

    if urls and code:
        if validate_extraction(code) and (
            (third_generation and len(urls) == 10) or (not third_generation and len(urls) == 3)
        ):
            return GootLoaderConfig(code, urls)
    return None
