rule RAN_Rook_Dec_2021_1 {
   meta:
        description = "Detect Rook ransomware"
        author = "Arkbird_SOLG"
        reference = "Internal Research"
        date = "2021-12-21"
        hash1 = "15a67f118c982ff7d094d7290b4c34b37d877fe3f3299840021e53840b315804"
        hash2 = "f87be226e26e873275bde549539f70210ffe5e3a129448ae807a319cbdcf7789"
        hash3 = "c2d46d256b8f9490c9599eea11ecef19fde7d4fdd2dea93604cee3cea8e172ac"
        tlp = "white"
        adversary = "Rook"
   strings:
        $s1 = { fc 41 5b eb 08 48 ff c6 88 17 48 ff c7 8a 16 01 db 75 0a 8b 1e 48 83 ee fc 11 db 8a 16 72 e6 8d 41 01 }
        $s2 = { 00 00 48 83 c4 28 48 83 c7 04 48 8d 5e fc 31 c0 8a 07 48 ff c7 09 c0 74 23 3c ef 77 11 48 01 c3 48 8b 03 48 0f c8 48 01 f0 48 89 03 eb e0 24 0f c1 e0 10 66 8b 07 48 83 c7 02 eb e1 48 8b 2d ?? ?? 00 00 48 8d be 00 f0 ff ff bb 00 10 00 00 50 49 89 e1 41 b8 04 00 00 00 48 89 da 48 89 f9 48 83 ec 20 ff d5 48 8d 87 ?? 02 00 00 80 20 7f 80 60 28 7f 4c 8d 4c 24 20 4d 8b 01 48 89 da 48 89 f9 ff d5 48 83 c4 28 5d 5f }
        $s3 = { 8a 16 f3 c3 48 8d 04 2f 83 f9 05 8a 10 76 21 48 83 fd fc 77 1b 83 e9 04 8b 10 48 83 c0 04 83 e9 04 89 17 48 8d 7f 04 73 ef 83 c1 04 8a 10 74 10 48 ff c0 88 17 83 e9 01 8a 10 48 8d 7f 01 }
        $s4 = { 09 c0 74 4a 8b 5f 04 48 8d 8c 30 ?? ?? ?? 00 48 01 f3 48 83 c7 08 ff 15 ?? ?? 00 00 48 95 8a 07 48 ff c7 08 c0 74 d7 48 89 f9 48 89 fa ff c8 f2 ae 48 89 e9 ff 15 ?? ?? 00 00 48 09 c0 74 09 48 89 03 48 83 c3 }
        $s5 = { 5e 48 89 f7 56 48 89 f7 48 c7 c6 00 ?? ?? 00 b2 0e 53 57 48 8d 4c 37 fd 5e 56 5b eb 2f 48 39 ce 73 32 56 5e ac 3c 80 72 0a 3c 8f 77 06 80 7e fe 0f 74 06 2c e8 3c 01 77 e4 48 39 ce 73 16 56 ad 28 d0 75 df 5f 0f c8 29 f8 01 d8 ab 48 39 ce 73 03 ac eb df 5b 5e 48 83 ec 28 48 8d be 00 ?? ?? 00 8b 07 09 c0 74 }
   condition:
        uint16(0) == 0x5A4D and filesize > 50KB and filesize < 800KB and all of ($s*) 
}
