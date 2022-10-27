rule RAN_GlobeImposter_Dec_2021_1 
{
   meta:
        description = "Detect GlobeImposter ransomware (reuse old build)"
        author = "Arkbird_SOLG"
        reference = "Internal Research"
        date = "2021-12-22"
        hash1 = "70fa0e970a0c29da67b5f1468996eecf7116256c2b7212fb6667b0fb92ad839d"
        hash2 = "39f5b60188d49196e6c10271a084a755f9553190898438b15107cdb950a4bbde"
        tlp = "Clear"
        adversary = "GlobeImposter"
   strings:
        $s1 = { b8 08 10 00 00 e8 c0 0d 00 00 53 56 57 8d 44 24 0c 33 f6 50 68 19 00 02 00 56 bf 48 20 40 00 bb 01 00 00 80 57 53 ff 15 04 10 40 00 85 c0 0f 85 87 00 00 00 55 8d 44 24 14 c7 44 24 14 00 08 00 00 50 8d 44 24 1c bd ac 20 40 00 50 56 56 55 ff 74 24 24 ff 15 00 10 40 00 ff b4 24 1c 10 00 00 8d 44 24 1c 50 ff 15 64 10 40 00 85 c0 74 41 56 8d 44 24 14 50 56 68 06 00 02 00 6a 01 56 56 57 53 ff 15 08 10 40 00 85 c0 75 25 ff b4 24 1c 10 00 00 ff 15 2c 10 40 00 03 c0 50 ff b4 24 20 10 00 00 6a 01 56 55 ff 74 24 24 ff 15 1c 10 40 00 ff 74 24 10 ff 15 0c 10 40 00 5d 5f 5e 5b 81 c4 08 10 00 00 }
        $s2 = { eb 2f 56 ff 75 0c 8b 75 10 56 ff 75 14 ff 15 10 10 40 00 53 ff 75 14 85 c0 75 0b ff 15 14 10 40 00 6a c4 58 eb 0a ff 15 14 10 40 00 89 37 33 c0 }
        $s3 = { 8d 85 c4 ef ff ff 50 ff d6 8d 85 c4 cf ff ff c7 45 c4 3c 00 00 00 89 45 d4 8d 85 c4 ef ff ff 6a 40 89 45 d8 8d 45 c4 5e 50 89 7d cc c7 45 d0 38 20 40 00 89 7d dc 89 7d e0 89 75 c8 ff 15 e0 10 40 00 85 c0 74 40 56 ff 75 fc 8b 35 a4 10 40 00 ff d6 68 00 01 00 00 57 ff 15 38 10 40 00 50 ff d6 6a 0f 57 ff 15 44 10 40 00 50 ff 15 48 10 40 00 57 8d 85 c4 df ff ff 50 6a 05 6a 04 ff 15 dc 10 }
        $s4 = { 8b f0 56 68 00 08 00 00 ff 15 84 10 40 00 57 33 db 53 68 f4 1f 40 00 56 ff 15 88 10 40 00 68 fc 1f 40 00 57 ff 15 70 10 40 00 53 68 80 00 00 00 6a 02 53 53 68 00 00 00 40 57 ff 15 30 10 40 00 83 f8 ff 74 1d 50 6a 20 68 24 11 40 00 68 d0 01 00 00 68 58 13 40 00 e8 5c f6 ff ff 57 e8 42 fe }
    condition:
          uint16(0) == 0x5A4D and filesize > 30KB and all of ($s*) 
}

