rule RAN_Diavol_Sept_2022_1 : ransomware diavol
{
   meta:
        description = "Detect Diavol ransomware"
        author = "Arkbird_SOLG"
        reference = "https://medium.com/walmartglobaltech/diavol-resurfaces-91dd93c7d922"
        date = "2022-10-04"
        hash1 = "aac969e36686f8f8517c111d30f8fb3b527988ebd31b3b762aec8d46e860eb9d"
        hash2 = "fb5ee29b98446d34520bf04a82996eefec3b5692710c5631458da63ef7e44fe4"
        hash3 = "708806f5e2e8bfa3d1e911e391ff2ccf1edcac05cc1df80439b8b867253423df"
        tlp = "Clear"
        adversary = "RAAS"
   strings:
        $s1 = { ba 04 01 00 00 48 2b d1 b9 04 01 00 00 48 2b ca 48 8d 44 54 60 74 37 4c 8d 4c 24 50 48 8d 94 11 fb fe ff 7f 4c 2b c8 48 85 d2 74 1d 45 0f b7 04 01 66 45 85 c0 74 12 66 44 89 00 48 83 c0 02 48 ff ca 48 ff c9 75 e0 eb 05 48 85 c9 75 04 48 83 e8 02 66 89 18 48 8d 95 70 01 00 00 48 8d 4c 24 30 41 b8 04 01 00 00 ff 15 [2] 01 00 4c 8d 4c 24 60 4c 8d 85 70 01 00 00 33 d2 33 c9 89 5c 24 28 48 89 5c 24 20 ff 15 ?? 3b 01 00 48 8b 8d 80 03 00 00 48 33 cc e8 58 05 00 00 48 8b 9c 24 a0 04 00 00 48 81 }
        $s2 = { c1 c1 e0 02 44 89 74 24 30 45 33 c0 89 44 24 74 48 8d 44 24 60 48 8b d3 48 89 44 24 28 49 8b 04 f7 48 8b cf c7 44 24 60 28 00 00 00 48 c7 44 24 6c 01 00 20 00 44 89 4c 24 68 48 89 44 24 20 4c 89 b4 24 84 00 00 00 44 89 b4 24 80 00 00 00 4c 8b ee ff 15 [2] 01 00 48 8b cf ff 15 [2] 01 00 b8 45 00 00 00 4c 8d 84 24 90 00 00 00 48 8b d5 49 8b cc c7 84 24 90 00 00 00 4a 00 50 00 66 89 84 24 94 00 00 00 c7 84 24 96 00 00 00 47 00 00 00 ff 15 [2] 01 00 48 8b d0 49 8b cc 48 8b d8 ff 15 [2] 01 00 48 8b c8 ff 15 ?? 47 01 00 48 8b d3 49 8b cc 48 8b f8 ff 15 [2] 01 00 8b 1f 8b f0 48 83 c7 04 83 ee 04 74 2d 90 48 8b cf ff 15 [2] 01 00 48 8d 57 20 48 8b c8 ff 15 [2] 01 00 4b 8b 0c ef 8b d3 48 83 c7 40 83 c3 08 83 c6 c0 48 89 04 0a 75 d4 48 }
        $s3 = { 48 8b 13 b8 77 00 00 00 48 8d 4d ff 66 89 45 23 b8 73 00 00 00 c7 45 ff 74 00 68 00 66 89 45 25 33 c0 c7 45 03 75 00 6e 00 c7 45 07 6b 00 46 00 c7 45 0b 69 00 6e 00 c7 45 0f 64 00 46 00 66 89 45 27 c7 45 13 69 00 6c 00 c7 45 17 65 00 20 00 c7 45 1b 2d 00 3e 00 c7 45 1f 20 00 25 00 e8 ?? 46 00 00 ba 18 00 00 00 33 c9 ff 15 [2] 01 00 48 85 c0 74 6b 48 8b 0b 4c 8d 05 51 fe ff ff 4c 8b c8 48 89 08 48 8b 4b 08 33 d2 48 89 48 08 48 8b 4b 10 48 89 48 10 48 8d 4d f7 48 89 4c 24 28 33 c9 c7 44 24 20 04 00 00 00 ff 15 [2] 01 00 8b 15 [2] 03 00 48 83 c9 ff 48 89 04 d6 ff c2 33 c0 89 15 [2] 03 00 48 8b 13 48 8b fa 66 f2 af bf 6b 00 00 00 48 f7 d1 48 8d 04 4a 48 89 03 48 8b 03 66 }
    condition:
        uint16(0) == 0x5A4D and filesize > 70KB and all of ($s*) 
}
