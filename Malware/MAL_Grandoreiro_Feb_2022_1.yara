rule MAL_Grandoreiro_Feb_2022_1 : Grandoreiro Banker
{
   meta:
        description = "Detect the Grandoreiro banker malware"
        author = "Arkbird_SOLG"
        reference = "https://twitter.com/ESETresearch/status/1494249519030018050?t=m5TG2yPf3k5icBmWqGzIlA&s=19"
        date = "2022-02-16"
        hash1 = "33b6bb191270f7b618b5651f68514ccdcfe06ee011cb94ea101136f4c5174dbd"
        hash2 = "84eceeeb5a459e922fb77f426a2a935b661c79f4b3c058d6923e1cdec91bb577"
        tlp = "Clear"
        adversary = "-"
   strings:
        $s1 = { 8b d8 8b 43 04 85 c0 74 22 80 7b 0c 00 75 06 50 e8 [2] ee ff 8b 43 04 50 e8 [2] ee ff 33 c0 89 43 04 8d 43 10 e8 [2] ed ff 5b c3 8b c0 53 56 8b f2 8b d8 8b 43 08 3b f0 74 1a 80 7b 14 00 74 0a 50 e8 [2] ee ff c6 43 14 00 89 73 08 8b c3 e8 a9 ff ff ff 5e }
        $s2 = { 8b ec 8b 45 10 50 83 7d 0c 01 1b c0 40 83 e0 7f 50 8b 45 08 50 e8 dd ff ff ff 5d c2 0c 00 90 ff 25 [3] 00 8b c0 ff 25 [3] 00 8b c0 ff 25 [3] 00 8b c0 ff 25 [3] 00 8b c0 ff 25 [3] 00 8b c0 ff 25 [3] 00 8b c0 ff 25 [3] 00 8b c0 ff 25 [3] 00 8b c0 ff 25 [3] 00 8b c0 ff 25 }
        $s3 = { 89 55 fc 8b 45 fc e8 [3] ff 33 c0 55 68 [3] 00 64 ff 30 64 89 20 8d 45 f8 ba [3] 00 e8 [3] ff 8d 45 f0 ba [3] 00 e8 [3] ff 8d 45 f4 ba [3] 00 e8 [3] ff 8d 45 ec ba [3] 00 e8 [3] ff 8d 45 e8 ba [3] 00 e8 [3] ff 33 c0 55 68 [3] 00 64 ff 30 64 89 20 6a 00 6a 00 6a 00 6a 00 8d 45 e0 e8 [2] ff ff 8b 45 e0 e8 [3] ff 50 e8 [3] ff 89 45 e4 83 7d e4 00 74 ?? 6a 00 68 00 00 00 80 6a 00 6a 00 8d 45 d4 e8 [2] ff ff 8b 55 d4 8d 4d d8 8b 45 fc e8 [2] ff ff ff 75 d8 ff 75 f8 ff 35 }
        $s4 = { 81 c4 fc fd ff ff c7 04 24 00 01 00 00 54 8d 44 24 08 50 e8 [3] ff 85 c0 74 15 b8 [3] 00 8d 54 24 04 b9 00 01 00 00 e8 [3] ff eb 0a b8 [3] 00 e8 [3] ff 81 }
        $s5 = { 33 c0 89 45 f4 8d 45 f0 50 8d 45 f4 50 6a 00 6a 00 0f b6 75 ef 56 6a 00 53 e8 15 e8 ff ff 83 7d f4 00 75 0d 33 c0 5a 59 59 64 89 10 e9 74 01 00 00 8b 45 f4 e8 [3] ff 89 45 e4 33 d2 55 68 [3] 00 64 ff 32 64 89 22 8d 45 f0 50 8d 45 f4 50 8b 45 f4 50 8b 45 e4 50 56 6a 00 53 e8 d0 e7 ff ff 85 c0 75 12 e8 [2] e7 ff 33 c0 5a 59 59 64 89 10 e9 2c 01 00 00 8b 45 e4 89 45 e0 8b 45 f0 48 85 c0 0f 8c c5 00 00 00 40 89 45 dc 80 7d ef 04 75 36 8b 5d e0 8b 33 56 6a 00 33 c9 b2 01 a1 [3] 00 e8 0c f0 ff ff 50 8d 45 d8 8b d6 e8 [2] e7 ff 8b 55 d8 8b 45 fc 8b 40 10 59 8b }
        $s6 = { 8b bd 68 fd ff ff 8d 85 58 fd ff ff e8 [2] ff ff ff b5 58 fd ff ff 68 [3] 00 ff 33 68 [3] 00 ff 36 68 [3] 00 68 [3] 00 68 [3] 00 68 [3] 00 8d 85 5c fd ff ff ba 09 00 00 00 e8 [3] ff 8b 85 5c fd ff ff 89 85 74 fd ff ff 8b 85 74 fd ff ff e8 [3] ff 50 89 bd 54 fd ff ff 8b 85 54 fd ff ff e8 [3] ff 50 e8 [3] ff 83 f8 01 1b c0 40 6a 32 e8 [3] ff eb 5e }
    condition:
        uint16(0) == 0x5A4D and filesize > 2000KB and all of ($s*) 
}
