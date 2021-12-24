rule RAN_Pay2Key_Dec_2021_1
{
    meta:
        description = "Detect the Pay2Key ransomware"
        author = "Arkbird_SOLG"
        date = "2021-12-21"
        reference = "Internal Research"
        hash1 = "c7d6719bbfb5baaadda498bf5ef49a3ada1d795b9ae4709074b0e3976968741e"
        hash2 = "947e357bfdfe411be6c97af6559fd1cdc5c9d6f5cea122bf174d124ee03d2de8"
        hash3 = "9a7daafc56300bd94ceef23eac56a0735b63ec6b9a7a409fb5a9b63efe1aa0b0"
        tlp = "white"
        adversary = "Pay2Key"
    strings:
        $s1 = { 6a ff 68 e8 55 4b 00 64 a1 00 00 00 00 50 83 ec 14 53 56 57 a1 70 60 4e 00 33 c5 50 8d 45 f4 64 a3 00 00 00 00 8b f9 8d 5f 10 c7 45 ec 00 00 00 00 53 6a 01 68 01 68 00 00 ff 77 04 ff 15 14 b0 4b 00 c7 45 e0 00 00 00 00 c7 45 e4 00 00 00 00 c7 45 e8 00 00 00 00 8d 45 f0 c7 45 fc 00 00 00 00 50 6a 00 6a 00 6a 01 ff 77 0c ff 33 ff 15 0c b0 4b 00 85 c0 74 39 ff 75 f0 e8 9d 0f 03 00 ff 75 f0 8b f0 6a 00 56 e8 d1 d7 04 00 83 c4 10 8d 45 f0 50 56 6a 00 6a 01 ff 77 0c ff 33 ff 15 0c b0 4b 00 85 }
        $s2 = { 8d 7b 18 57 6a 00 6a 00 68 0c 80 00 00 ff 36 ff 15 30 b0 4b 00 85 c0 75 0e ff 15 84 b1 4b 00 50 68 c4 a5 4c 00 eb 53 8b 43 08 2b 43 04 6a 00 50 ff 73 04 ff 37 ff 15 38 b0 4b 00 85 c0 75 16 ff 15 84 b1 4b 00 50 68 e0 a5 4c 00 e8 13 fa ff ff 83 c4 08 eb 37 8d 43 10 50 6a 00 ff 37 68 10 66 00 00 ff 36 ff 15 34 b0 4b 00 85 c0 75 1e ff 15 84 b1 4b 00 50 68 fc a5 4c 00 e8 e4 f9 ff ff 83 c4 08 6a 00 ff 36 ff 15 1c b0 4b 00 8d 4d 08 e8 df 06 00 00 8b c3 8b 4d f4 64 89 0d 00 00 00 00 59 5f 5e 5b 8b 4d f0 33 cd e8 5b a0 06 00 }
        $s3 = { 50 8d 85 28 ff ff ff 68 18 a6 4c 00 50 ff 15 40 b3 4b 00 68 20 a6 4c 00 e8 e0 f6 ff ff 8b b5 1c e6 ff ff 83 c4 10 8d 4d 0c e8 df 03 00 00 8b c6 8b 4d f4 64 89 0d 00 00 00 00 59 5f 5e 5b 8b 4d f0 33 cd e8 5b 9d 06 00 8b e5 }
        $s4 = { 6a 00 ff 15 bc b3 4b 00 ff 75 c4 8d 45 dc 50 57 ff 15 ac b3 4b 00 8d 55 d0 8b c8 e8 82 5f 00 00 85 c0 75 47 8d 4d a8 e8 36 fe fc ff f3 0f 7e 00 8b 40 08 66 0f d6 45 d0 89 45 d8 8d 45 d0 50 51 8b ce e8 cb ec ff ff 8b f0 83 c4 08 89 75 c4 c6 45 fc 02 83 fe }
    condition:
      uint16(0) == 0x5A4D and filesize > 600KB and all of ($s*) 
}

