rule RAN_NightSky_Jan_2022_1
{
    meta:
        description = "Detect NightSky ransomware"
        author = "Arkbird_SOLG"
        date = "2022-01-07"
        reference = "Internal Research"
        hash1 = "8c1a72991fb04dc3a8cf89605fb85150ef0e742472a0c58b8fa942a1f04877b0"
        hash2 = "-"
        tlp = "white"
        adversary = "-"
        level = "Experimental"
    strings:
        $s1 = { 8b 01 e3 48 5c b3 16 73 8c d2 0d c3 8a 88 13 7d ba 19 37 ab e4 75 12 1d c7 5a 29 3a df 8a d8 c7 b1 d6 e5 33 f0 0f 4c 5c 6a 30 9b b6 94 2d 42 88 56 a9 8e 54 6a 5a 14 87 22 d6 d7 a8 6c 31 44 7c c4 7e 72 96 56 c8 77 72 6d 91 56 13 d6 2b 1e 27 19 ca 05 0a 42 fc 59 30 b8 ff d1 58 c8 75 6b 37 7c 36 d5 d0 25 ae 00 58 01 b0 ef 2e 2b bc 1d e6 92 31 0f c7 98 c7 d6 15 12 67 76 4b ad 88 51 b8 9d 68 06 }
        $s2 = { b8 4d 5a 00 00 41 f6 c5 75 48 81 fa 9f 4f b2 16 66 39 01 0f 84 13 00 00 00 2b c0 d3 fe 48 81 c4 78 01 00 00 66 41 0f be e9 5e 5d c3 48 63 41 3c 48 f7 c5 06 07 fa 4a f5 81 3c 08 50 45 00 00 e9 00 00 00 00 0f 85 cf ff ff ff 44 8b 84 08 88 00 00 00 44 84 e7 f5 44 89 44 24 30 45 85 c0 e9 00 00 00 00 0f 84 b0 ff ff ff 44 8b 8c 08 8c 00 00 00 66 }
        $s3 = { 48 8b c4 48 d3 db 4c 0f a4 f6 f3 40 86 f3 48 b9 00 01 00 00 00 00 00 00 66 41 0f bd dd d3 e6 48 8d 5c 25 80 49 0f bf f6 66 2b f0 48 81 e3 f0 ff ff ff 66 d3 f6 48 2b d9 48 0f 4f f3 66 87 f6 48 8b e3 49 63 f0 57 9c 49 0f b7 fd 66 8b f6 48 8b f0 }
        $s4 = { 48 8d 44 24 50 48 2b e8 86 c1 48 99 90 66 d3 c2 66 44 0f ab c2 e9 00 00 00 00 48 8d 54 3c 50 66 0f b3 d9 66 0f c8 66 d3 d9 8b cf 48 f7 d0 b8 f4 40 06 25 f8 d3 c0 40 02 c7 32 04 2a e9 00 00 00 00 88 02 e9 00 00 00 00 0f 84 15 00 00 00 48 ff c7 41 f6 c5 3d f8 48 81 ff 04 01 00 00 0f 82 b7 ff ff ff 48 8d 6c 24 50 48 8b d5 9f 41 0f bf cc 48 8b ce 9f f7 d0 49 63 c0 48 8b 05 b7 4f ba ff e9 }
    condition:
       uint16(0) == 0x5A4D and filesize > 300KB and all of ($s*) 
}
