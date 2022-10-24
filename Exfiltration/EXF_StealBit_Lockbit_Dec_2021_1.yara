rule MAL_StealBit_Lockbit_Dec_2021_1 
{
   meta:
        description = "Detect StealBit used by Lockbit gang for exfiltrate the stolen data"
        author = "Arkbird_SOLG"
        reference = "Internal Research"
        date = "2021-12-23"
        hash1 = "107d9fce05ff8296d0417a5a830d180cd46aa120ced8360df3ebfd15cb550636"
        hash2 = "3407f26b3d69f1dfce76782fee1256274cf92f744c65aa1ff2d3eaaaf61b0b1d"
        hash3 = "8b5f88aeaad4d50c90e0c6dabc5145ef73063e098b22ed7820168aa0954505b2"
        hash4 = "61ac7ac908791456f2f5827dfd85be27b02027383f76dfd31aba7eff89c1aaee"
        tlp = "Clear"
        adversary = "RAAS"
   strings:
        $s1 = { 83 ec 20 83 65 fc 00 8d 4d fc e8 b6 18 00 00 84 c0 74 41 6a 02 59 8d 45 f8 89 4d e4 89 45 e0 8d 55 e8 89 4d ec 8d 45 f0 68 40 38 00 00 8d 4d e0 c7 45 f8 20 b2 40 00 c7 45 fc 2c b2 40 00 c7 45 f0 38 b2 40 00 c7 45 f4 54 b2 40 00 89 45 e8 e8 d1 16 00 00 }
        $s2 = { 73 00 68 00 65 00 6c 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 00 00 63 00 6f 00 6d 00 63 00 74 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 00 00 00 00 00 00 00 00 05 00 00 00 00 00 00 00 0f 00 00 00 00 00 00 00 14 00 00 00 00 00 00 00 19 00 00 00 00 00 00 00 1e 00 00 00 00 00 00 00 0d 0a 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff 25 44 e0 }
        $s3 = { 8b 45 e4 8b 55 e0 8b 4d f8 2b ce 8b 80 10 00 04 00 03 c2 89 45 c8 8b 45 fc 03 c8 3b 4d 0c 0f 47 4d 0c 83 c2 04 89 4d bc 03 d6 51 8d 48 04 e8 bc fb ff ff 8b 55 bc 59 8d 78 04 8b 45 fc 8d 0c 07 3b ca 75 16 3b 55 0c 73 11 ff 75 0c 8b 55 dc e8 9b fb ff ff 03 f8 8b 45 fc 59 83 7d d0 00 74 19 8b 55 e0 8b c8 ff 75 c8 ff 75 08 8d 14 16 e8 05 fd ff ff 59 59 8b c8 eb 02 33 c9 8b 55 10 2b f9 3b fa 7e 18 8b 5d 14 8d 04 31 03 45 ec 89 03 8b 45 fc 03 c1 e9 42 ff ff ff }
        $s4 = { 56 57 6a 2e 5e 6a 33 59 6a 38 58 6a 36 66 89 85 c8 fc ff ff 58 6a 63 66 89 85 ca fc ff ff 33 c0 66 89 85 cc fc ff ff 58 6a 6d 66 89 85 ba fc ff ff 58 6a 64 5f 6a 61 5a 6a 6e 66 89 85 bc fc ff ff 33 c0 66 89 85 c0 fc ff ff 58 6a 69 66 89 85 b0 fc ff ff 58 6a 76 66 89 85 b2 fc ff ff 33 c0 66 89 85 b4 fc ff ff 66 89 85 a8 fc ff ff 66 89 95 ae fc ff ff 66 89 95 a2 fc ff ff 5a 6a 6d 58 6a 73 66 89 85 66 ff ff ff 66 89 bd be fc ff ff 66 89 bd a4 fc ff ff 5f 6a 69 58 66 89 85 6a ff ff ff 33 c0 6a 6d 66 89 85 6c ff ff ff 58 6a 70 66 89 85 5a ff ff ff 33 c0 66 89 bd 68 ff ff ff 66 89 bd 5c ff ff ff 5f 6a 63 66 89 85 60 ff ff ff 58 6a 6f 66 89 85 4e ff ff ff 58 66 89 85 50 ff ff ff 6a 6d 58 66 89 85 52 ff ff ff 33 c0 66 89 b5 c4 fc ff ff 66 89 8d c6 fc ff ff 66 89 b5 b8 fc ff ff 66 89 b5 ac fc ff ff 66 89 b5 a0 fc ff ff 66 89 95 a6 fc ff ff 66 89 b5 64 ff ff ff 66 89 b5 58 ff ff ff 66 89 bd 5e ff ff ff 66 89 b5 4c ff ff ff 66 89 85 54 ff ff ff 6a 6e 58 6a 6c 66 89 85 42 ff ff ff 58 6a 73 66 89 85 44 ff ff ff 58 6a 6f 66 89 85 46 ff ff ff 33 c0 66 89 85 48 }
        $s5 = { 51 8d 4c 24 48 e8 d0 0a 00 00 8b c8 e8 a7 0a 00 00 50 e8 cb b9 ff ff 8b c8 e8 57 17 00 00 ff d0 51 8d 4c 24 58 e8 0e 0a 00 00 8b c8 e8 5a 06 00 00 50 e8 ab b9 ff ff 8b c8 e8 37 17 00 00 ff d0 51 8d 8c 24 a8 00 00 00 e8 49 09 00 00 8b c8 e8 20 09 00 00 50 e8 88 b9 ff ff 8b c8 e8 14 17 00 00 ff d0 51 8d 4c 24 23 e8 a0 08 00 00 8b c8 e8 7d 08 00 00 50 e8 68 b9 ff ff 8b c8 e8 f4 16 00 00 ff d0 51 8d 4c 24 68 e8 ec 07 00 00 8b c8 e8 f7 05 00 00 50 e8 48 b9 ff ff 8b c8 e8 d4 16 00 00 ff d0 51 8d 4c 24 2e e8 57 07 00 00 8b c8 e8 34 07 00 00 50 e8 28 b9 ff ff 8b c8 e8 b4 16 00 00 ff d0 51 8d 4c 24 78 e8 85 06 00 00 8b c8 e8 5c 06 00 00 50 e8 08 b9 ff ff 8b c8 e8 94 16 00 00 ff d0 51 8d 8c 24 88 00 00 00 e8 be 05 00 00 8b c8 e8 94 05 00 00 50 e8 e5 b8 ff ff 8b c8 e8 71 16 }
        $s6 = { 8d 7e 18 89 0f 8b d7 8b 44 24 24 8b 0e 89 47 04 e8 29 f0 ff ff 33 c9 89 46 08 b8 00 00 10 00 89 4e 20 89 46 10 89 4e 24 39 4f 04 7f 15 7c 04 39 07 73 0f 8b 07 05 ff 0f 00 00 25 00 f0 ff ff 89 46 10 8b 8e b4 02 00 00 8b 16 50 8b 49 20 e8 40 f0 ff ff 83 64 24 10 00 33 d2 59 8d 4e 48 89 46 14 89 4c 24 08 42 89 51 f4 8b 46 20 89 01 8b 46 24 89 41 04 8b 4e 10 e8 1a ea ff ff 8b 4c 24 08 89 41 08 8b 4e 14 e8 0b ea ff ff 8b 4c 24 08 83 79 08 00 89 41 0c 0f 84 d8 fe ff ff 85 c0 0f 84 d0 fe ff ff 33 d2 42 01 96 a8 02 00 00 01 96 b0 02 00 00 8b 46 10 01 46 20 83 56 24 00 8b 46 24 3b 47 04 7f 1e 7c 07 8b 46 20 3b 07 73 15 8b 44 24 0c 83 c1 38 40 89 4c 24 08 89 44 24 0c 83 f8 }
    condition:
        uint16(0) == 0x5A4D and filesize > 30KB and 3 of ($s*) 
}

