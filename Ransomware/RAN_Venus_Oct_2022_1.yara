rule RAN_Venus_Oct_2022_1 : venus ransomware
{
   meta:
        description = "Detect venus ransomware"
        author = "Arkbird_SOLG"
        reference = "https://www.bleepingcomputer.com/forums/t/777945/venus-ransomware-support-help-topic-venus-readmehtml/"
        date = "2022-10-15"
        hash1 = "ee036f333a0c4a24d9aa09848e635639e481695a9209474900eb71c9e453256b"
        hash2 = "fa7ba459236c7b27a0429f1961b992ab87fc8b3427469fd98bfc272ae6852063"
        hash3 = "52f7ace0de098c3c820416b601d62c4f56c9b20b569fa625bf242b625521f147"
        tlp = "Clear"
        adversary = "Unknown"
   strings:
        $s1 = { 57 68 00 01 00 00 e8 9e 07 00 00 8b 3d e8 a1 41 00 8b f0 68 ?? a5 41 00 68 ?? a5 41 00 68 ?? a5 41 00 68 ?? a5 41 00 56 89 75 f8 ff d7 83 c4 14 8d 45 f4 50 8d 45 fc 50 6a 00 68 06 00 02 00 6a 00 6a 00 6a 00 56 8b 35 08 a0 41 00 68 02 00 00 80 ff d6 ff 75 fc ff 15 a0 c8 43 00 8b 45 f8 68 [2] 41 00 50 68 ?? a6 41 00 50 ff d7 8b 7d f8 8d 45 f4 83 c4 10 50 8d 45 fc 50 6a 00 68 06 00 02 00 6a 00 6a 00 6a 00 57 68 02 00 00 80 ff d6 83 7d f4 02 75 10 ff 75 fc ff 15 18 a0 41 00 5f 5e 5b 8b e5 5d c3 53 ff 15 28 a1 41 00 03 c0 50 53 6a 01 6a 00 68 ?? a6 41 00 ff 75 fc e8 f7 b8 fe ff 83 c4 18 ff 75 fc ff 15 a0 c8 43 00 68 ?? a6 41 00 68 ?? a6 41 00 ff 15 88 a0 41 00 50 ff 15 90 a0 41 00 6a 00 6a 00 6a 00 68 00 00 00 }
        $s2 = { 50 ff 15 28 a1 41 00 8d 04 45 01 00 00 00 50 8d 85 28 f7 ff ff 50 6a 01 6a 00 57 ff 75 fc ff 15 04 a0 41 00 ff 75 fc ff 15 18 a0 41 00 e8 6c fb ff ff 85 c0 74 50 8d 85 28 f7 ff ff c7 45 ac 3c 00 00 00 89 45 bc 0f 57 c0 8d 45 ac c7 45 b0 00 00 00 00 50 c7 45 b4 00 00 00 00 c7 45 b8 [2] 41 00 c7 45 c0 ?? a5 41 00 0f 11 45 c4 c7 45 e4 00 00 00 00 0f 11 45 d4 ff 15 8c a1 41 00 85 c0 0f 84 f4 fe ff ff 56 e8 f2 08 00 00 83 3d 64 af 43 00 05 c7 45 ec 00 00 00 00 c7 45 e8 00 00 00 00 76 1f 8d 45 ec 50 ff 15 5c a1 41 00 50 ff 15 e0 a0 41 00 85 c0 74 0a 8d 45 e8 50 ff 15 54 a1 41 00 6a 44 8d 85 48 ff ff ff 6a 00 50 e8 [2] 00 00 83 c4 0c 8d 85 d8 e2 ff ff 68 10 04 00 00 50 6a 00 ff 15 e4 a0 41 00 0f 57 c0 c7 85 48 ff ff ff 44 00 00 00 68 10 04 00 00 0f 29 45 90 e8 5a 08 00 00 8b f0 8d 85 d8 e2 ff ff 50 68 ?? a5 41 00 56 ff 15 c4 a1 41 00 83 c4 0c 33 c0 66 89 85 78 ff ff ff 8d 45 90 50 8d 85 48 ff ff ff 50 6a 00 6a 00 68 00 00 00 08 6a 00 6a 00 6a 00 56 68 ?? a5 41 00 ff 15 d8 a0 41 00 6a 65 ff 15 94 a0 }
        $s3 = { 6a 00 6a 00 8d 45 fc 50 57 6a 01 56 53 ff 15 f0 aa 43 00 85 c0 74 74 68 00 01 00 00 e8 45 0e 00 00 ff 35 dc aa 43 00 a3 50 af 43 00 68 ?? a5 41 00 50 ff 15 e8 a1 41 00 83 c4 0c 6a 00 68 80 00 00 00 6a 02 6a 00 6a 00 68 00 00 00 40 ff 35 50 af 43 00 ff 15 1c a1 41 00 6a 00 8b f0 8d 45 f8 50 ff 75 fc 57 56 ff 15 24 a1 41 00 53 e8 34 0e 00 00 57 e8 2e 0e 00 00 56 ff 15 48 a1 41 00 a1 50 }
   condition:
        uint16(0) == 0x5A4D and filesize > 60KB and all of ($s*)
}
