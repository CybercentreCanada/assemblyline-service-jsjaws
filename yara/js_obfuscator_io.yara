rule JS_obfuscator_io {

    meta:
        id = "22kXYAtxLg84HyamwhPEF4"
        fingerprint = "c7bde665bdd669f381db4bd75cff399c2f71ee03051d7da8471c6aa53f27392e"
        version = "1.0"
        first_imported = "2022-10-13"
        last_modified = "2022-10-13"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "CCCS"
        author = "reveng@CCCS"
        description = "Detects javascript file obfuscated with obfuscator.io (https://obfuscator.io)"
        category = "TECHNIQUE"
        technique = "obfuscation"
        report = "TA22-0101"
        mittre_attr = "T1027"
        sample = "f43235257a4793dc3916aed7bb688e8a83862bb66d131127c9633701726267dd"

    strings:
        $push_shift = /\['push'\][^\s]{,30}\['shift'\]/
        $CFF = /'[a-zA-Z]{5}': ?function/
        $b64_array = /const [a-zA-Z0-9_-]{2,40} ?= ?\[('[A-Za-z0-9=\/+]{4,20}', ?){10,}/
    condition:
        #push_shift == 2 and
        #CFF > 10 and
        #b64_array == 1
}
