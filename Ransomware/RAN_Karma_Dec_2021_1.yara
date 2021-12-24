rule RAN_Karma_Dec_2021_1 
{
   meta:
        description = "Detect Karma ransomware"
        author = "Arkbird_SOLG"
        reference = "Internal Research"
        date = "2021-12-23"
        hash1 = "34629751d8202be456dcf149b516afefc980a9128dd6096fd6286fee530a0d20"
        hash2 = "4dec9a9044631caef283c7f39a576e4e5c1cc1e6a97ce5c60936a3a3d0097818"
        hash3 = "84d24a16949b5a89162411ab98ab2230128d8f01a3d3695874394733ac2a1dbd"
        tlp = "white"
        adversary = "Karma"
   strings:
        $s1 = { 83 e9 04 66 90 0f b7 02 8d 49 02 66 89 01 8d 52 02 66 85 c0 75 ef 68 00 08 00 00 6a 08 ff 15 ?? 40 40 00 50 ff 15 ?? 40 40 00 8b f8 b9 [2] 40 00 2b cf 89 [15] 00 00 0f b7 04 11 8d 52 02 66 89 02 66 85 c0 75 f1 68 [2] 40 00 6a 00 6a 00 6a 00 6a 02 6a 01 6a 00 6a 00 6a 00 68 90 01 00 00 6a 00 6a 00 6a 00 6a 2d ff 15 1c 40 40 00 6a 00 89 }
        $s2 = { 55 8b ec 83 ec 40 b8 00 01 00 00 53 56 8b 75 08 8b d9 57 8b fa 83 c6 20 8b 56 fc 8d 76 fc 85 d2 75 0d 83 e8 20 8b c8 85 c0 7f ed 85 c9 74 10 b9 00 00 00 80 85 d2 78 07 d1 e9 48 85 d1 74 f9 33 c9 8d 70 ff 33 d2 89 4d e0 89 55 e4 89 4d e8 89 4d ec 89 4d f0 89 4d f4 89 4d f8 89 4d fc 89 4d c0 89 4d c4 89 4d c8 89 4d cc 89 4d d0 89 4d d4 89 4d d8 89 4d dc 85 f6 78 42 66 0f 1f 44 00 00 8d 55 c0 8d 4d e0 e8 35 fb ff ff 8b 55 08 8b c6 c1 e8 05 8b ce 83 e1 1f 8b 04 82 d3 e8 a8 01 74 10 57 53 8d 55 }
        $s3 = { 85 ff 74 10 b9 00 00 00 80 85 d2 78 07 d1 e9 48 85 d1 74 f9 2b f0 79 3c 0f 10 45 e0 f7 de 0f 10 4d f0 0f 11 5d e0 0f 11 55 f0 0f 10 d8 0f 10 d1 0f 10 c5 0f 10 cc 0f 10 2b 0f 10 63 10 0f 11 03 0f 11 5d c0 0f 11 55 d0 0f 11 6d a0 0f 11 65 b0 0f 11 4b 10 56 8d 55 c0 8d 4d 80 e8 fd fb ff ff 83 c4 04 33 c0 0f 1f 84 00 00 00 00 00 0f 10 44 05 e0 0f 10 4c 05 80 66 0f ef c8 0f 11 4c 05 e0 83 c0 10 83 f8 20 7c e5 56 8d 55 a0 8d 4d 80 e8 c9 fb ff ff 8d 55 80 83 c4 04 8b c3 2b d3 b9 02 00 00 00 66 66 0f 1f 84 00 00 00 00 00 8d 40 10 0f 10 40 f0 0f 10 4c 02 f0 66 0f ef c8 0f 11 48 f0 83 }
        $s4 = { 8b 5d 10 56 57 bf fe ff ff ff c7 45 c0 65 00 00 00 c7 45 c4 78 00 00 00 8d 73 02 c7 45 c8 70 00 00 00 2b fb c7 45 cc 61 00 00 00 c7 45 d0 6e 00 00 00 c7 45 d4 64 00 00 00 c7 45 d8 20 00 00 00 c7 45 dc 33 00 00 00 c7 45 e0 32 00 00 00 c7 45 e4 2d 00 00 00 c7 45 e8 62 00 00 00 c7 45 ec 79 00 00 00 c7 45 f0 74 00 00 00 c7 45 f4 65 00 00 00 c7 45 f8 20 00 00 00 c7 45 fc 6b 00 00 00 8d 0c 37 b8 cd cc cc cc f7 e1 8d 76 14 83 e2 f0 0f b6 44 15 c0 88 46 ea 0f b6 44 15 c4 88 46 eb 0f b6 44 15 c8 88 46 ec 0f b6 44 15 cc 88 46 ed 8d 04 37 83 f8 }
    condition:
         uint16(0) == 0x5A4D and filesize > 10KB and all of ($s*) 
}