from gootloader_modified import goot_decode_modified
from gootloader import gootDecode, goot3detected
import argparse
import dataclasses
from typing import List
from utils import GootLoaderConfig




# Argument parsing
parser = argparse.ArgumentParser()
parser.add_argument('jsFilePath', help='Path to the GOOTLOADER JS file.')
parser.add_argument('--unsafe-uris', action="store_true", help='Do not convert http(s) to hxxp(s)')
parser.add_argument('--payload-path', required=False, default="DecodedJsPayload.js_", help='Path to the payload file that will be written')
parser.add_argument('--stage2-path', required=False, default="GootLoader3Stage2.js_", help='Path to the GootLoader3 stage 2 file that will be written')
args = parser.parse_args()


third_generation: bool = False
try:
    third_generation = goot_decode_modified(args.jsFilePath, args.unsafe_uris, args.payload_path, args.stage2_path)

    if third_generation:
        goot_decode_modified(args.stage2_path, args.unsafe_uris, args.payload_path, args.stage2_path)
except:
    """Fallback on the unmodified script"""
    gootDecode(args.jsFilePath, args.unsafe_uris, args.payload_path, args.stage2_path)
    if goot3detected:
        gootDecode(args.stage2_path, args.unsafe_uris, args.payload_path, args.stage2_path)

