rule RAN_AVOSLocker_Dec_2021_1
{
    meta:
        description = "Detect AVOSLocker ransomware"
        author = "Arkbird_SOLG"
        date = "2021-12-18"
        reference = "Internal Research"
        hash1 = "718810b8eeb682fc70df602d952c0c83e028c5a5bfa44c506756980caf2edebb"
        hash2 = "bd88d415032eb24091c352fc0732b31116f44a78d9333037bd7608289608d3cd"
	hash3 = "c0a42741eef72991d9d0ee8b6c0531fc19151457a8b59bdcf7b6373d1fe56e02"
        tlp = "Clear"
        adversary = "AVOSLocker"
    strings:
        $s1 = { 55 8b ec 6a ff 68 [3] 00 64 a1 00 00 00 00 50 83 ec 44 a1 08 80 4d 00 33 c5 89 45 f0 53 56 57 50 8d 45 f4 64 a3 00 00 00 00 8b f1 8b 3d 08 20 4b 00 68 00 00 00 f0 6a 01 6a 00 6a 00 56 c7 06 00 00 00 00 ff d7 85 c0 75 2b ff 15 ?? 20 4b 00 6a 08 6a 01 6a 00 68 ?? 6f 4b 00 56 8b d8 ff d7 85 c0 75 11 6a 28 6a 01 50 68 ?? 6f 4b 00 56 ff d7 85 c0 74 1e 8b c6 8b 4d f4 64 89 0d 00 00 00 00 59 5f 5e 5b 8b 4d f0 33 cd e8 ?? f8 fd ff 8b e5 5d c3 53 ff 15 ?? 20 4b 00 68 ?? 6f 4b 00 8d 4d d8 e8 [2] fc ff 8d 45 d8 c7 45 fc 00 00 00 00 50 8d 4d b0 e8 a5 00 00 00 68 [2] 4d 00 8d 45 b0 50 e8 }
        $s2 = { 55 8d 6c 24 8c 83 ec 74 6a ff 68 [2] 4a 00 64 a1 00 00 00 00 50 81 ec ?? 00 00 00 a1 08 80 4d 00 33 c5 89 45 70 53 56 57 50 8d 45 f4 64 a3 00 00 00 00 89 65 f0 c7 45 ec f8 05 4e 00 0f 1f 00 a1 1c 06 4e 00 83 f8 ff 0f 84 [2] 00 00 6a ff 8d 4d 18 51 8d 4d 54 51 8d 4d 50 51 50 ff 15 6c 20 4b 00 85 c0 74 d9 c7 45 68 00 00 00 00 c7 45 6c 00 00 00 00 c7 45 68 00 00 00 00 c7 45 6c 07 00 00 00 33 c0 66 89 45 58 8b 55 18 8b ca 8d 71 02 66 8b 01 83 c1 02 66 85 c0 75 f5 2b ce d1 f9 51 52 8d 4d 58 e8 [2] 01 00 c7 45 fc 00 00 00 00 ff 75 18 e8 55 ?? 06 00 83 c4 04 c6 45 fc 01 }
        $s3 = { 8d 84 24 e8 00 00 00 51 52 50 e8 [2] 05 00 83 c4 0c c7 84 24 a8 00 00 00 00 08 00 00 8d 84 24 a8 00 00 00 6a 00 6a 00 50 8d 84 24 f4 08 00 00 50 6a 00 6a 00 8d 84 24 00 01 00 00 50 ff 15 28 20 4b 00 85 c0 0f 85 78 00 00 00 0f 28 05 [2] 4c 00 33 c9 0f 11 44 24 1c c7 44 24 3c [4] 0f 28 05 [2] 4c 00 0f 11 44 24 2c 66 c7 44 24 40 ?? 00 0f 1f 00 8a 44 24 1c 30 44 0c 1d 41 83 f9 24 72 f2 c6 44 24 41 00 ff 15 ?? 20 4b 00 50 8d 44 24 21 50 6a 02 e8 [2] 05 00 83 c4 04 50 e8 [2] ff ff 83 c4 0c 32 c0 5f 5e 5b 8b 8c 24 e0 10 00 00 33 cc e8 [2] 01 00 81 c4 e8 10 00 00 c3 8d 84 24 b0 00 00 00 50 8d 84 24 a0 00 00 00 50 6a 00 68 00 80 00 00 ff b4 24 b8 00 00 00 8d 84 24 fc 08 00 00 50 6a 08 6a 01 ff 15 20 20 4b 00 85 }
        $s4 = { b8 18 14 00 00 e8 ?? dc 01 00 a1 08 80 4d 00 33 c5 89 45 fc 8b 4d 0c 8b c1 8b 55 10 83 e1 3f c1 f8 06 6b c9 38 53 56 8b 04 85 78 fe 4d 00 8b 75 08 57 8b fe 8b 44 08 18 8b 4d 14 89 85 f0 eb ff ff 03 ca 33 c0 89 8d f4 eb ff ff ab ab ab 8b fa 3b d1 0f 83 c4 00 00 00 8b b5 f4 eb ff ff 8d 85 50 f9 ff ff 3b fe 73 21 0f b7 0f 83 c7 02 83 f9 0a 75 09 6a 0d 5a 66 89 10 83 c0 02 66 89 08 83 c0 02 8d 4d f8 3b c1 72 db 6a 00 6a 00 68 55 0d 00 00 8d 8d f8 eb ff ff 51 8d 8d 50 f9 ff ff 2b c1 d1 f8 50 8b c1 50 6a 00 68 e9 fd 00 00 e8 62 bb ff ff 8b 75 08 83 c4 20 89 85 e8 eb ff ff 85 c0 74 51 33 db 85 c0 74 35 6a 00 8d 8d ec eb ff ff 2b c3 51 50 8d 85 f8 eb ff ff 03 c3 50 ff b5 f0 eb ff ff ff 15 ?? 21 4b 00 85 c0 74 26 03 9d ec eb ff ff 8b 85 e8 eb ff ff }
    condition:
       uint16(0) == 0x5A4D and filesize > 300KB and all of ($s*) 
}
