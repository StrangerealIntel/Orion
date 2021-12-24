rule RAN_Diavol_Dec_2021_1
{
    meta:
        description = "Detect the Diavol ransomware (x86 version)"
        author = "Arkbird_SOLG"
        date = "2021-12-20"
        reference = "Internal Research"
        hash1 = "2723c9b143ef85be072e18f670e06335c45bdb0ba369381f97f96658ae3503b0"
        hash2 = "79456569b6aba9d00e641ce0067a0b18e4fe69232d6c356201d1ab62ebfe4c8f"
        tlp = "white"
        adversary = "Diavol"
    strings:
        $s1 = { 83 ec 1c a1 04 60 41 00 33 c5 89 45 f8 83 3d c0 6e 41 00 ff 56 57 0f 84 97 00 00 00 8d 45 e8 50 ff 15 ?? 20 41 00 0f b7 4d f6 0f b7 55 f4 0f b7 45 f2 51 0f b7 4d f0 52 8b 15 ?? db 41 00 50 51 68 ?? 49 41 00 52 ff 15 80 21 41 00 8b 4d 08 8b f0 8d 45 0c 50 a1 ?? db 41 00 51 ba f6 27 00 00 2b d6 52 8d 0c 70 51 e8 4e 0a 00 00 83 c4 28 83 f8 ff 74 3f 8b 15 ?? db 41 00 8d 7a fe 66 8b 4f 02 83 c7 02 66 85 c9 75 f4 8b 0d ?? 49 41 00 89 0f 6a 00 8d 4d e4 51 8b 0d c0 6e 41 00 03 c6 8d 44 00 02 50 52 51 c7 45 e4 00 00 00 00 ff 15 ?? 20 41 00 8b 4d f8 5f 33 cd }
        $s2 = { 68 04 01 00 00 8d 8d ec fb ff ff 51 68 ?? 49 41 00 ff 15 ?? 20 41 00 6a 00 6a 00 8d 95 f4 fd ff ff 52 8d 85 ec fb ff ff 50 6a 00 6a 00 ff 15 ?? 21 41 00 8b 4d fc 33 cd e8 d0 00 00 00 8b }
        $s3 = { 55 8b ec 83 ec 10 a1 04 60 41 00 83 65 f8 00 83 65 fc 00 53 57 bf 4e e6 40 bb bb 00 00 ff ff 3b c7 74 0d 85 c3 74 09 f7 d0 a3 08 60 41 00 eb 65 56 8d 45 f8 50 ff 15 ?? 20 41 00 8b 75 fc 33 75 f8 ff 15 ?? 21 41 00 33 f0 ff 15 ?? 21 41 00 33 f0 ff 15 ?? 21 41 00 33 f0 8d 45 f0 50 ff 15 ?? 21 41 00 8b 45 f4 33 45 f0 33 f0 3b }
        $s4 = { 83 ec 58 a1 04 60 41 00 33 c5 89 45 f8 8b 45 08 53 56 57 8b fa 50 57 89 45 c8 89 4d c4 ff 15 ?? 21 41 00 6a 00 8b d8 ff 15 0c 20 41 00 8b f0 53 56 ff 15 08 20 41 00 8d 55 a8 52 6a 18 53 ff 15 18 20 41 00 8b 45 c8 50 8b 45 c4 8d 4d a8 8b d7 e8 c8 fe ff ff 83 c4 04 6a 00 89 45 c8 ff 15 0c 20 41 00 8b 4d b0 8b 55 ac 51 52 56 8b f8 ff 15 10 20 41 00 50 57 89 45 c0 ff 15 08 20 41 00 8b 45 b0 8b 4d ac 68 46 00 66 00 6a 00 6a 00 57 50 51 6a 00 6a 00 56 ff 15 1c 20 41 00 8b 4d b0 8b 45 ac 89 45 d0 0f af c1 33 d2 03 c0 03 c0 52 89 45 e0 8d 45 cc 50 8b 45 c8 50 51 89 4d d4 8b 4d c0 52 51 57 89 55 f4 c7 45 cc 28 00 00 00 c7 45 d8 01 00 20 00 89 55 dc 89 55 f0 89 55 ec ff 15 14 20 41 00 8b 55 b0 8b 45 ac 68 46 00 66 00 6a 00 6a 00 57 52 50 6a 00 6a 00 56 ff 15 1c 20 41 00 8b 55 c4 8b 04 95 ?? c6 41 00 6a 00 8d 4d cc 51 8b 4d b0 50 51 6a 00 53 56 ff 15 04 20 41 00 57 8b 3d 00 20 41 00 ff d7 56 ff d7 8b 4d f8 5f 5e 33 cd }
    condition:
      uint16(0) == 0x5A4D and filesize > 90KB and all of ($s*) 
}