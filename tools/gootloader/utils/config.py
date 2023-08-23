from typing import List


class GootLoaderConfig:
    def __init__(self, code: str, urls: List[str]):
        self.code = code
        self.urls = urls
