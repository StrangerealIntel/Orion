rule RAN_HelloKitty_Dec_2021_1
{
    meta:
        description = "Detect the HelloKitty ransomware"
        author = "Arkbird_SOLG"
        date = "2021-12-20"
        reference = "Internal Research"
        hash1 = "c7d6719bbfb5baaadda498bf5ef49a3ada1d795b9ae4709074b0e3976968741e"
        hash2 = "947e357bfdfe411be6c97af6559fd1cdc5c9d6f5cea122bf174d124ee03d2de8"
        hash3 = "9a7daafc56300bd94ceef23eac56a0735b63ec6b9a7a409fb5a9b63efe1aa0b0"
        tlp = "Clear"
        adversary = "RAAS"
    strings:
        $s1 = { 68 00 00 00 f0 6a 01 6a 00 6a 00 50 c7 06 00 00 00 00 ff 15 08 20 ?? 00 85 c0 75 08 b8 c4 ff ff ff 5e 5d c3 57 ff 75 0c 8b 7d 10 57 ff 75 14 ff 15 00 20 ?? 00 6a 00 ff 75 14 85 c0 75 0f ff 15 04 20 ?? 00 5f b8 c4 ff ff ff 5e 5d c3 ff 15 04 20 ?? 00 89 3e 33 c0 5f }
        $s2 = { 56 68 [3] 00 68 [3] 00 68 [3] 00 6a 14 e8 [2] ff ff 8b f0 83 c4 10 85 f6 74 15 ff 75 10 8b ce ff 75 0c ff 75 08 ff 15 [3] 00 ff d6 eb 0c ff 75 0c ff 75 08 ff 15 [3] 00 8b 4d fc 33 cd 5e e8 [2] ff ff 8b e5 }
        $s3 = { 0f b6 c0 2b cb 41 f7 d8 68 40 01 00 00 1b c0 23 c1 89 85 b4 fe ff ff 8d 85 bc fe ff ff 57 50 e8 [2] ff ff 83 c4 0c 8d 85 bc fe ff ff 57 57 57 50 57 53 ff 15 ?? 21 ?? 00 8b f0 8b 85 b8 fe ff ff 83 fe ff 75 2d 50 57 57 53 e8 9f fe ff ff 83 c4 10 8b f8 83 fe ff 74 07 56 ff 15 [3] 00 8b c7 8b 4d fc 5f 5e 33 cd 5b e8 [2] ff ff 8b e5 5d c3 8b 48 04 2b 08 c1 f9 02 89 8d b0 fe ff ff 80 bd e8 fe ff ff 2e 75 18 8a 8d e9 fe ff ff 84 c9 74 29 80 f9 2e 75 09 80 bd ea fe ff ff 00 74 1b 50 ff b5 b4 fe ff ff 8d 85 e8 fe ff ff 53 50 e8 38 fe ff ff 83 c4 10 85 c0 75 95 8d 85 bc fe ff ff 50 56 ff 15 ?? 21 ?? 00 85 c0 8b 85 b8 fe ff ff 75 ac 8b 10 8b 40 04 8b 8d b0 fe ff ff 2b c2 c1 f8 02 3b c8 0f 84 67 ff ff ff 68 [3] 00 2b c1 6a 04 50 8d 04 8a 50 e8 [2] 00 00 83 c4 }
        $s4 = { 56 e8 ac ff ff ff 59 57 57 57 8b d8 57 2b de d1 fb 53 56 57 57 ff 15 [3] 00 89 45 fc 85 c0 74 34 50 e8 [2] ff ff 8b f8 59 85 ff 74 1c 33 c0 50 50 ff 75 fc 57 53 56 50 50 ff 15 [3] 00 85 }
    condition:
      uint16(0) == 0x5A4D and filesize > 30KB and all of ($s*) 
}

