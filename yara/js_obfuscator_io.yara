rule JS_obfuscator_io {

    meta:
        id = "22kXYAtxLg84HyamwhPEF4"
        fingerprint = "670b1afe7ce98b198c6124990291cf2c8504c114f9eb8c323be4ffe853851550"
        version = "2.2"
        first_imported = "2022-10-13"
        last_modified = "2023-05-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "CCCS"
        author = "reveng@CCCS"
        description = "Detects javascript file obfuscated wiht obfuscator.io (https://obfuscator.io)"
        category = "TECHNIQUE"
        technique = "OBFUSCATION"
        report = "TA22-0101"
        mittre_attr = "T1027"
        sample = "f43235257a4793dc3916aed7bb688e8a83862bb66d131127c9633701726267dd"

    strings:
        $push_shift = /\['push'\][^\s]{,30}\['shift'\]/
        $CFF = /'[a-zA-Z]{5}': ?function/
        $b64_array = /const [a-zA-Z0-9_-]{2,40} ?= ?\[('[A-Za-z0-9=\/+]{4,20}', ?){10,}/
    condition:
        // two closely located push_shifts on identical variables
        for 1 i in (1..#push_shift\2):(
            @push_shift[i*2] - @push_shift[i*2-1] >=20 and
            @push_shift[i*2] - @push_shift[i*2-1] <=300 and
            uint8(@push_shift[i*2]-1) == uint8(@push_shift[i*2]-1)
        )
        or
        #push_shift == 2 and
        #CFF > 10 and
        #b64_array == 1
}
