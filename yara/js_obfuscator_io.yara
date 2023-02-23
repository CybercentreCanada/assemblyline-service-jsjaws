rule JS_obfuscator_io {

    meta:
        id = "22kXYAtxLg84HyamwhPEF4"
        fingerprint = "023b22718a4987ca06dc616479455918a0761c3d7a34828f2cb6657f8342ee19"
        version = "2.1"
        first_imported = "2022-10-13"
        last_modified = "2023-02-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "CCCS"
        author = "reveng@CCCS"
        description = "Detects javascript file obfuscated with obfuscator.io (https://obfuscator.io)"
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
            @push_shift[i*2] - @push_shift[i*2-1] >=34 and
            @push_shift[i*2] - @push_shift[i*2-1] <=61 and
            uint8(@push_shift[i*2]-1) == uint8(@push_shift[i*2]-1)
        )
        or
        #push_shift == 2 and
        #CFF > 10 and
        #b64_array == 1
}
