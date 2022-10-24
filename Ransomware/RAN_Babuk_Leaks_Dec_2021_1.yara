rule RAN_Babuk_Leaks_Dec_2021_1
{
    meta:
        description = "Detect Babuk leaked ransomware (Feb 2021 build - also reused from the leaks)"
        author = "Arkbird_SOLG"
        date = "2021-12-19"
        reference = "Internal Research"
        hash1 = "049e53f72c8afa5ccb850429d55a00e2fbe799e68247fd13f5058146cf0f4cf8"
        hash2 = "c994996fdfcae2af56b9d726c31e4442cd5c157fdc9337a00fc0e84acf34f254"
        tlp = "Clear"
        adversary = "Babuk"
    strings:
        $s1 = { 6a 2c 8b 4d f0 8b 14 8d 00 40 41 00 52 8b 45 e8 50 ff 15 20 50 41 00 89 45 fc 83 7d fc 00 0f 84 a6 01 00 00 8d 4d f4 51 6a 24 8d 55 b8 52 6a 00 8b 45 fc 50 ff 15 00 50 41 00 85 c0 0f 84 7e 01 00 00 83 7d bc 01 0f 84 74 01 00 00 83 7d bc 03 0f 84 6a 01 00 00 8d 4d dc 51 8d 55 f4 52 6a 00 8b 45 f8 50 6a 01 8b 4d fc 51 ff 15 08 50 41 00 85 c0 0f 85 ea 00 00 00 ff 15 ec 50 41 00 3d ea 00 00 00 0f 85 d9 00 00 00 8b 55 f4 52 e8 84 e5 00 00 83 c4 04 89 45 f8 83 7d f8 00 0f 84 c0 00 00 00 8d 45 dc 50 8d 4d f4 51 8b 55 f4 52 8b 45 f8 50 6a 01 8b 4d fc 51 ff 15 08 50 41 00 85 c0 0f 84 90 00 00 00 6b 75 f0 24 03 75 f8 b9 09 00 00 00 8d bd 70 ff ff ff f3 a5 6a 24 8b 95 70 ff ff ff 52 8b 45 e8 50 ff 15 20 50 41 00 89 45 ec 83 7d ec 00 }
        $s2 = { 68 ?? 3c 40 00 6a 00 6a 00 ff 15 98 50 41 00 eb 0a e9 b0 00 00 00 e9 ab 00 00 00 c7 45 a8 00 00 00 00 68 ?? 3c 40 00 8b 55 c8 52 8b 45 e8 50 e8 86 9b ff ff 83 c4 0c 0f b6 c8 83 f9 01 75 0c 8b 55 a8 52 e8 02 f9 ff ff 83 c4 04 e8 ea 94 ff ff ff 15 04 51 41 00 89 45 c0 83 7d c0 00 74 3f b8 41 00 00 00 66 89 45 f0 eb 0c 66 8b 4d f0 66 83 c1 01 66 89 4d f0 0f b7 55 f0 83 fa 5a 7f 1f 8b 45 c0 83 e0 01 74 0d 0f b7 4d f0 51 e8 b9 fa ff ff 83 c4 04 8b 55 c0 d1 ea 89 55 c0 eb cc 68 ?? 3c 40 00 8b 45 c8 50 8b 4d e8 51 e8 0a 9b ff ff 83 c4 0c 0f b6 d0 85 d2 75 0c 8b 45 a8 50 e8 87 f8 ff ff 83 c4 04 c7 45 b4 00 00 00 00 eb 09 8b 4d b4 83 c1 01 89 4d b4 8b 55 b4 3b 55 fc 73 13 6a 01 6a 00 68 2c 42 41 00 e8 fc 7e 00 00 83 c4 0c eb dc 6a ff 6a 01 8b 45 e4 50 8b 4d fc 51 ff 15 9c 50 41 00 c7 45 }
        $s3 = { 83 ec 10 c7 45 f4 ff ff ff ff c7 45 f8 00 40 00 00 8d 45 f0 50 8b 4d 08 51 6a 13 6a 00 6a 02 e8 1e 89 00 00 85 c0 0f 85 9d 00 00 00 8b 55 f8 52 e8 f8 84 00 00 83 c4 04 89 45 08 83 7d 08 00 74 7f 8d 45 f8 50 8b 4d 08 51 8d 55 f4 52 8b 45 f0 50 e8 f2 88 00 00 85 c0 75 5a c7 45 fc 00 00 00 00 eb 09 8b 4d fc 83 c1 01 89 4d fc 8b 55 fc 3b 55 f4 73 3e 8b 45 fc c1 e0 05 8b 4d 08 8b 54 01 0c }
        $s4 = { 8b 4d c0 51 e8 fd 90 00 00 c7 45 94 00 00 00 00 e9 44 f7 ff ff e9 88 00 00 00 83 3d 5c 42 41 00 00 74 7f 6a 00 6a 00 6a 00 6a 00 8b 55 08 52 ff 15 40 50 41 00 50 8b 45 08 50 6a 00 68 e9 fd 00 00 ff 15 cc 50 41 00 89 45 90 8b 4d 90 51 e8 b6 8c 00 00 83 c4 04 89 45 bc 6a 00 6a 00 8b 55 90 52 8b 45 bc 50 8b 4d 08 51 ff 15 40 50 41 00 50 8b 55 08 52 6a 00 68 e9 fd 00 00 ff 15 cc 50 41 00 8b 45 e8 50 8b 4d bc 51 68 b8 3a 40 00 e8 66 ab ff ff 83 c4 0c 8b 55 bc 52 e8 9a 8c 00 00 }
    condition:
       uint16(0) == 0x5A4D and filesize > 30KB and all of ($s*) 
}