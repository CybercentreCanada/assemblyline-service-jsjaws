from typing import List
import dataclasses

class GootLoaderConfig:
    def __init__(self, urls: List[str], code: str, urls_concat:str):
        self.urls = urls
        self.code = code
        self.urls_concat = urls_concat