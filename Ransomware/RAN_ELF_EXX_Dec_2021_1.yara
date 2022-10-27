rule RAN_ELF_EXX_Dec_2021_1 
{
   meta:
        description = "Detect ELF version of EXX ransomware"
        author = "Arkbird_SOLG"
        reference = "Internal Research"
        date = "2021-12-23"
        hash1 = "196eb5bfd52d4a538d4d0a801808298faadec1fc9aeb07c231add0161b416807"
        hash2 = "6b667bb7e4f3f2cb6c6f2d43290f32f41ae9f0d6ed34b818d78490050f7582a1"
        tlp = "Clear"
        adversary = "EXX"
   strings:
        $s1 = { b8 00 00 00 00 e8 ?? fb ff ff 48 8b 40 08 48 8d 95 ?? ee ff ff 48 8d 4a 10 48 89 c2 be 10 00 00 00 48 89 cf e8 ?? ?? 01 00 89 45 ?? 83 7d ?? 00 0f 85 ?? 01 00 00 b8 00 00 00 00 e8 ?? ?? ff ff 48 8b 40 10 48 8d 95 ?? ee ff ff 48 8d 4a 28 48 89 c2 be 10 00 00 00 48 89 cf e8 ?? ?? 01 00 89 45 ?? 83 7d ?? 00 0f 85 ?? 01 00 00 48 8d 85 ?? ee ff ff 48 83 c0 10 48 89 c7 e8 ?? 13 01 00 48 83 c0 07 48 c1 e8 03 48 89 85 ?? ee ff ff 48 8d b5 ?? ?? ff ff 48 8d 95 ?? e9 ff ff 48 8d 85 ?? ee ff ff 48 83 ec 08 48 8d 8d ?? ef ff ff 51 49 89 f1 41 b8 30 00 00 00 b9 00 00 00 00 48 8d 35 ?? 1b 00 00 48 89 c7 e8 ?? ?? 00 00 48 83 c4 10 89 45 ?? 83 7d ?? 00 0f 85 ?? 00 00 00 48 8d ?? ?? 60 03 00 }
        $s2 = { 48 89 c7 e8 ?? ?? ff ff 48 89 45 f0 48 83 7d f0 00 0f 84 ?? 01 00 00 48 8b 45 d8 48 89 c7 e8 ?? 02 00 00 e9 ?? ?? 00 00 48 8b 45 e8 48 83 c0 13 48 89 45 e0 48 8b 45 e8 0f b6 40 12 3c 04 75 ?? 48 8b 45 e0 48 8d ?? ?? ?? 01 00 48 89 }
        $s3 = { 48 81 ec b8 00 00 00 48 89 bd 48 ff ff ff 48 8b 85 48 ff ff ff 48 89 c7 e8 ?? ?? ff ff 48 89 c3 b8 00 00 00 00 e8 ?? eb ff ff 48 8b 40 20 48 89 c7 e8 ?? ?? ff ff 48 01 d8 48 83 c0 02 48 89 c7 e8 f9 ?? ff ff 48 89 45 e8 48 83 7d e8 00 }
        $s4 = { 61 6e 69 7c 2e 63 61 62 7c 2e 63 70 6c 7c 2e 63 75 72 7c 2e 64 69 61 67 63 61 62 7c 2e 64 69 61 67 70 6b 67 7c 2e 64 6c 6c 7c 2e 64 72 76 7c 2e 68 6c 70 7c 2e 69 63 6c 7c 2e 69 63 6e 73 7c 2e 69 63 6f 7c 2e 69 73 6f 7c 2e 69 63 73 7c 2e 6c 6e 6b 7c 2e 69 64 78 7c 2e 6d 6f 64 7c 2e 6d 70 61 7c 2e 6d 73 63 7c 2e 6d 73 70 7c 2e 6d 73 73 74 79 6c 65 73 7c 2e 6d 73 75 7c 2e 6e 6f 6d 65 64 69 61 7c 2e 6f 63 78 7c 2e 70 69 66 7c 2e 70 72 66 7c 2e 72 74 70 7c 2e 73 63 72 7c 2e 73 68 73 7c 2e 73 70 6c 7c 2e 73 79 73 7c 2e 74 68 65 6d 65 7c 2e 74 68 65 6d 65 70 61 63 6b 7c 2e 65 78 65 7c 2e 62 61 74 7c 2e 63 6d 64 7c 2e 75 72 6c 7c 2e 6d 75 69 }
    condition:
        uint16(0) == 0x457f and filesize > 80KB and all of ($s*) 
}

