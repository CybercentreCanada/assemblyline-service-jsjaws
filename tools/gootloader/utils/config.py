from dataclasses import dataclass
from typing import List


@dataclass
class PersistenceInformation:
    js_file_name: str
    scheduled_task_name: str
    original_file_name: str


@dataclass
class GootLoaderConfig:
    code: str
    urls: List[str]
    final_stage_path: str
    persistence: PersistenceInformation
