rule RAN_Cerber2021_Jan_2022_1
{
    meta:
        description = "Detect the new variant of Cerber (December 2021)"
        author = "Arkbird_SOLG"
        date = "2022-01-08"
        reference = "https://www.bleepingcomputer.com/news/security/new-cerber-ransomware-targets-confluence-and-gitlab-servers/"
        hash1 = "078de7d019f5f1e546aa29af7123643bd250341af71506e6256dfee8f245a2a7"
        hash2 = "eba0482a5b1232db451b1a745dd8e99defb9f1194b070e2f5c20eeb251296a86"
        tlp = "white"
        adversary = "-"
    strings:
        $s1 = { 8d 8d ?? ff ff ff c6 45 fc 08 e8 [2] 00 00 8d }
        $s2 = { 33 c0 c7 85 3c fe ff ff 0f 00 00 00 89 85 38 fe ff ff 88 85 28 fe ff ff c7 45 fc 04 00 00 00 f6 85 48 fe ff ff 01 74 1f 83 a5 48 fe ff ff fe 83 bd 14 fe ff ff 10 72 0f 8b 8d 00 fe ff ff 51 e8 [2] 03 00 83 c4 04 33 c0 c7 45 c8 0f 00 00 00 89 45 c4 88 45 b4 6a 6c c6 45 fc 0e e8 [2] 03 00 8b f0 83 c4 04 89 b5 44 fe ff ff c6 45 fc 0f 85 f6 0f 84 0a 01 00 00 6a 48 e8 [2] 03 00 8b f8 83 c4 04 89 bd 24 fe ff ff 33 c0 c6 45 fc 10 3b f8 0f 84 c4 00 00 00 50 68 [2] 49 00 8d 8d 00 fe ff ff c7 85 14 fe ff ff 0f 00 00 00 89 85 10 fe ff ff 88 85 00 fe ff ff e8 [2] 00 00 c6 45 fc 11 83 8d 48 fe ff ff 04 33 c0 6a 01 68 [2] 49 00 8d 8d 28 fe ff ff c7 85 3c fe ff ff 0f 00 00 00 89 85 38 fe ff ff 88 85 28 fe ff ff e8 [2] 00 00 c7 45 fc 12 00 00 00 83 8d 48 fe ff ff 08 6a 10 e8 [2] 03 00 8b f0 83 c4 04 89 b5 1c fe ff ff c7 45 fc 13 00 00 00 85 f6 74 1e 6a 00 8b ce e8 [2] 00 00 8d 55 b4 c7 06 64 ?? 47 00 c7 46 04 50 ?? 47 00 89 56 0c eb 02 33 f6 56 57 8d 95 00 fe ff ff 8d 8d 28 fe ff ff }
        $s3 = { 8d 44 24 0c 50 e8 [2] 00 00 8b 44 24 0c bf 08 00 00 00 c7 44 24 34 00 00 00 00 39 7c 24 20 73 04 8d 44 24 0c 68 78 ?? 48 00 50 ff 15 f0 ?? 4a 00 83 c4 08 84 c0 75 63 8b 44 24 0c 39 7c 24 20 73 04 8d 44 24 0c 68 6c ?? 48 00 50 ff 15 f0 ?? 4a 00 83 c4 08 84 c0 75 42 8b 44 24 0c 39 7c 24 20 73 04 8d 44 24 0c 68 60 ?? 48 00 50 ff 15 f0 ?? 4a 00 83 c4 08 84 c0 75 21 8b 44 24 0c 39 7c 24 20 73 04 8d 44 24 0c 68 54 ?? 48 00 50 ff 15 f0 ?? 4a 00 83 c4 08 84 c0 74 03 83 ce 49 39 7c 24 }
        $s4 = { 8b 95 40 fe ff ff 8b 4a 04 8b 84 0d 4c fe ff ff 8d 8c 0d 40 fe ff ff 83 c8 02 83 79 38 00 75 03 83 c8 04 6a 00 50 e8 [2] ff ff 6a 00 6a 00 6a 00 68 [2] 48 00 68 [2] 48 00 6a 00 ff 15 98 ?? 47 00 8d 8d a0 fe ff ff c7 45 fc ff ff ff ff e8 [2] 00 00 8d 85 a0 fe ff ff 50 c7 85 a0 fe ff ff 00 ?? 47 00 e8 [2] 03 00 83 c4 04 32 c0 8b 4d f4 64 89 0d 00 00 00 00 }
    condition:
       uint16(0) == 0x5A4D and filesize > 100KB and all of ($s*) 
}
