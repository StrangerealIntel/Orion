rule RAN_Cuba_Dec_2021_1
{
    meta:
        description = "Detect the Cuba ransomware"
        author = "Arkbird_SOLG"
        date = "2021-12-20"
        reference = "Internal Research"
        hash1 = "482b160ee2e8d94fa6e4749f77e87da89c9658e7567459bc633d697430e3ad9a"
        hash2 = "936119bc1811aeef01299a0150141787865a0dbe2667288f018ad24db5a7bc27"
        tlp = "white"
        adversary = "Cuba"
    strings:
        $s1 = { 50 8d 84 24 88 02 00 00 68 60 9f 41 00 50 ff 15 ?? 51 41 00 83 c4 18 8d 44 24 20 50 8d 44 24 28 50 8d 44 24 24 50 6a ff 8d 44 24 28 50 6a 01 8d 84 24 90 02 00 00 50 ff 15 b4 51 41 00 8b d8 89 5c 24 14 85 db 74 0c 81 fb ea 00 00 00 0f 85 b9 00 00 00 8b 74 24 18 33 ff 47 39 7c 24 1c 0f 82 95 00 00 00 8b 5c 24 0c ff 36 8d 84 24 7c 02 00 00 50 8d 84 24 80 0a 00 00 68 7c 9f 41 00 50 ff 15 ?? 51 41 00 83 c4 10 83 7e 04 00 7c 55 8d 44 24 28 50 8d 84 24 7c 0a 00 00 50 ff 15 ?? 50 41 00 89 44 24 10 83 f8 ff 74 39 ff 36 8d 84 24 7c 02 00 00 50 8d 84 24 80 0a 00 00 68 8c 9f 41 00 50 ff 15 ?? 51 41 00 83 c4 10 8d 84 24 78 0a 00 00 8b cb 50 e8 ef f7 ff ff ff 74 24 10 ff 15 ?? 50 41 00 47 83 c6 0c 3b 7c 24 }
        $s2 = { 8d 85 fc f7 ff ff 50 8d 86 00 08 00 00 50 ff 15 ?? 50 41 00 8d 85 f8 f7 ff ff b9 00 04 00 00 50 51 56 8d 85 fc f7 ff ff 89 8d f8 f7 ff ff 50 ff 15 ?? 50 41 00 85 c0 75 07 66 89 06 8b de eb 06 03 9d e8 f7 ff ff 6a 00 8d 85 f0 f7 ff ff 50 6a 00 8d 85 fc f7 ff ff 50 ff 15 bc 50 41 00 85 c0 74 18 8b 85 f0 f7 ff ff 89 83 00 10 00 00 8b 85 f4 f7 ff ff 89 83 04 10 00 00 8b 9d ec f7 ff ff b8 08 10 00 00 03 d8 03 f0 68 00 04 00 00 8d 85 fc f7 ff ff 89 9d ec f7 ff ff 50 ff b5 e4 f7 ff ff 47 ff 15 ?? 50 41 00 85 }
        $s3 = { 6a 01 6a 00 8b f1 8b fa 6a 00 56 ff 15 04 50 41 00 85 c0 75 09 5f b8 99 ff ff ff 5e 5d c3 57 ff 75 08 ff 36 ff 15 08 50 41 00 85 c0 75 09 5f b8 98 ff ff ff 5e 5d c3 6a 00 ff 36 ff 15 0c 50 41 00 5f 33 c0 5e }
        $s4 = { 68 3f 00 0f 00 53 53 88 5d d3 ff 15 18 50 41 00 8b f8 85 ff 75 04 32 c0 eb 64 6a 2c 56 57 ff 15 ?? 50 41 00 8b f0 85 f6 74 4b 83 7d 08 ff 74 1b 53 53 53 53 53 53 53 6a ff ff 75 08 6a ff 56 ff 15 ?? 50 41 00 85 c0 0f 95 45 d3 8d 45 f8 50 6a 24 8d 45 d4 50 53 56 ff 15 ?? 50 41 00 85 }
    condition:
       uint16(0) == 0x5A4D and filesize > 90KB and all of ($s*) 
}