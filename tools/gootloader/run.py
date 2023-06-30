from logging import Logger
from typing import Optional

from tools.gootloader.gootloader_modified import goot_decode_modified
from tools.gootloader.GootLoaderAutoJsDecode import gootDecode
from tools.gootloader.utils import GootLoaderConfig


def run(js_file_path: str, unsafe_uris: bool = False, payload_path: str = None, stage2_path: str = None, log: Logger = print) -> Optional[GootLoaderConfig]:
    third_generation: bool = False
    urls: str = ""
    code: str = ""

    try:
        third_generation, urls, code = goot_decode_modified(js_file_path, unsafe_uris, payload_path, stage2_path, log)
        if third_generation:
            """The path of the second stage never changes"""
            _, urls, code =  goot_decode_modified(stage2_path, unsafe_uris, payload_path, stage2_path, log)
    except Exception as e:
        log(f"Falling back on GootLoaderAutoJsDecode due to {e}")
        """Fallback on the unmodified script"""
        try:
            third_generation, urls, code = gootDecode(js_file_path, unsafe_uris, payload_path, stage2_path, log)
            if third_generation:
                print("calling again")
                _, urls, code = gootDecode(stage2_path, unsafe_uris, payload_path, stage2_path, log)
        except Exception as e:
            log(f"Error when running GootLoaderAutoJsDecode due to {e}")

    if(urls and code):
        return GootLoaderConfig(code, urls)
    else:
        return None
