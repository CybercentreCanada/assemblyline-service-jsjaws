from gootloader_modified import goot_decode_modified
from gootloader import gootDecode

from typing import Optional
from utils import GootLoaderConfig



def run(js_file_path: str) -> Optional[GootLoaderConfig]:
    third_generation: bool = False
    urls: str = ""
    code: str = ""

    try:
        third_generation, urls, code = goot_decode_modified(js_file_path)
        if third_generation:
            """The path of the second stage never changes"""
            _, urls, code =  goot_decode_modified("GootLoader3Stage2.js_")  
    except:
        """Fallback on the unmodified script"""
        third_generation, urls, code = gootDecode(js_file_path)
        if third_generation:
            print("calling again")
            _, urls, code = gootDecode("GootLoader3Stage2.js_")

    if(urls and code):
        return GootLoaderConfig(code, urls)
