rule RAN_Royal_Rumble_Dec_2022_2 : royal_rumble ransomware x64
{
   meta:
        description = "Detect the Royal Rumble ransomware (x64)"
        author = "Arkbird_SOLG"
        reference = "Internal Research"
        date = "2022-12-20"
        hash1 = "9db958bc5b4a21340ceeeb8c36873aa6bd02a460e688de56ccbba945384b1926"
        hash2 = "2598e8adb87976abe48f0eba4bbb9a7cb69439e0c133b21aee3845dfccf3fb8f"
        hash3 = "c24c59c8f4e7a581a5d45ee181151ec0a3f0b59af987eacf9b363577087c9746"
        tlp = "Clear"
        adversary = "-"
   strings:
        $s1 = { 33 d2 48 8d 8d c0 6b 00 00 41 b8 00 02 00 00 e8 d8 67 16 00 48 8d 15 a1 6c 23 00 48 8d 8d c0 6b 00 00 ff 15 8c e6 18 00 0f 57 c0 c7 44 24 70 68 00 00 00 33 c0 48 8d 95 c0 6b 00 00 89 45 d4 48 8d 0d b6 6c 23 00 48 89 44 24 60 45 33 c9 48 8d 44 24 50 45 33 c0 48 89 44 24 48 48 8d 44 24 70 48 89 44 24 40 4c 89 64 24 38 4c 89 64 24 30 44 89 64 24 28 44 89 64 24 20 0f 11 44 24 74 0f 11 45 84 0f 11 45 94 0f 11 45 a4 0f 11 45 b4 0f 11 45 c4 0f 11 44 24 50 ff 15 8f e3 18 00 4c 8b ac 24 d0 6e 00 00 4c 8b a4 24 d8 6e 00 00 48 8b b4 24 08 6f 00 00 48 8b 9c 24 00 6f 00 00 85 c0 74 26 48 8b 4c 24 50 ba 10 27 00 00 ff 15 73 e3 18 00 48 8b 4c 24 50 ff 15 b0 e3 18 00 48 8b 4c 24 58 ff 15 a5 e3 18 }
        $s2 = { b8 80 10 00 00 e8 8e 62 16 00 48 2b e0 48 8b 05 94 31 25 00 48 33 c4 48 89 84 24 70 10 00 00 48 8b da 48 8b f1 48 89 54 24 40 4c 8d 05 f7 71 23 00 48 8d 4c 24 50 e8 cd 03 00 00 48 8d 4c 24 50 48 83 7c 24 68 08 48 0f 43 4c 24 50 33 ed 48 89 6c 24 30 89 6c 24 28 c7 44 24 20 02 00 00 00 45 33 c9 45 33 c0 ba 00 00 00 40 ff 15 10 fc 18 00 48 8b f8 48 83 f8 ff 0f 85 c6 00 00 00 48 8b 54 24 68 48 83 fa 08 72 37 48 8d 14 55 02 00 00 00 48 8b 4c 24 50 48 8b c1 48 81 fa 00 10 00 00 72 19 48 83 c2 27 48 8b 49 f8 48 2b c1 48 83 c0 f8 48 83 }
        $s3 =  { 33 d2 41 b8 00 10 00 00 48 8d 4c 24 70 e8 83 7d 16 00 4c 8b 86 10 03 00 00 48 8d 15 05 6b 23 00 48 8d 4c 24 70 e8 7b ef ff ff 89 6c 24 48 48 89 6c 24 20 4c 8d 4c 24 48 44 8b c0 48 8d 54 24 70 48 8b cf ff 15 0c fb 18 00 48 8b cf ff 15 e3 f9 18 00 48 8b 54 24 68 48 }
    condition:
        uint16(0) == 0x5A4D and filesize > 150KB and all of ($s*)
}
