rule RAN_Conti_Feb_2022_1 : Conti Ransomware
{
   meta:
        description = "Detect the Conti ransomware (x64)"
        author = "Arkbird_SOLG"
        reference = "Internal Research"
        date = "2022-02-25"
        hash1 = "930ec6d08e9d29fa23805ff9784cb0d78b1dc4cc4d58daa0e653dfe478c45d3a"
        hash2 = "ea524e8b0dd046561b59a8d4da5a122aeff02036c87bb03056437a1d0f584039"
        hash3 = "ed4afa874e75b7bac665b9bcbf1d8e1324d4f9263c862755101cd79bb087ad45"
        hash4 = "1dea453e5344898c9a66309bd6d1cf6e21c56eb1427c026aac84b14a6b23f7fc"
        tlp = "Clear"
        adversary = "RAAS"
   strings:
        $s1 = { f7 e9 03 d1 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 2b c8 b8 09 04 02 81 83 c1 7f f7 e9 03 d1 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 2b c8 88 4c 3c 39 48 ff c7 48 83 ff 24 72 ?? 0f b7 44 24 7c 48 8d 54 24 39 44 0f b7 4c 24 7a 48 8d 4d 80 44 0f b7 44 24 78 89 44 24 20 ff 15 [2] 01 00 8b d8 85 c0 74 32 48 8b 3d [2] 01 00 ba 0f 00 00 00 41 b8 14 b4 02 e8 44 8d 4a 50 e8 [2] fe ff 44 8d 04 1b 4c 89 74 24 20 4c 8d 4c 24 68 48 8b cf 48 8d 55 80 ff d0 48 8b 3d [2] 01 00 ba 0f 00 00 00 41 b8 14 b4 02 e8 44 8d 4a 50 e8 [2] fe ff 4c 8d 4c 24 68 4c 89 74 24 20 44 8b c6 48 8d 95 80 00 00 00 48 8b cf ff d0 48 8b 3d [2] 01 00 ba 0f 00 00 00 41 b8 14 b4 02 e8 44 8d 4a 50 e8 [2] fe ff 4c 8d 4c 24 68 4c 89 74 24 20 41 b8 04 }
        $s2 = { 48 89 5c 24 08 48 89 74 24 18 57 48 83 ec 20 40 8a f1 8b 05 [2] 01 00 33 db 85 c0 7f 12 33 c0 48 8b 5c 24 30 48 8b 74 24 40 48 83 c4 20 5f c3 ff c8 89 05 [2] 01 00 e8 73 fa ff ff 40 8a f8 88 44 24 38 83 3d [2] 01 00 02 75 35 e8 86 fb ff ff e8 25 06 00 00 e8 9c 06 00 00 89 1d [2] 01 00 e8 a1 fb ff ff 40 8a cf e8 6d fd ff ff 33 d2 40 8a ce e8 87 fd ff ff 84 c0 0f 95 c3 8b c3 eb }
        $s3 = { 48 8b 0d [2] 01 00 4c 8b c3 33 d2 ff 15 [2] 00 00 48 85 c0 74 d4 eb 0d e8 60 08 00 00 c7 00 0c 00 00 00 33 c0 48 83 c4 20 5b c3 cc cc 48 85 c9 74 37 53 48 83 ec 20 4c 8b c1 33 d2 48 8b 0d [2] 01 00 ff 15 [2] 00 00 85 c0 75 17 e8 2b 08 00 00 48 8b d8 ff 15 [2] 00 00 8b c8 e8 63 07 00 00 89 03 48 83 c4 20 5b c3 cc cc cc 48 89 5c 24 08 4c 89 4c 24 20 57 48 83 ec 20 49 8b d9 49 }
        $s4 = { 48 83 c0 27 48 83 e0 e0 48 89 48 f8 eb 11 48 85 d2 74 0a 48 8b ca e8 [2] 00 00 eb 02 33 c0 4c 8d 04 5d 02 00 00 00 48 89 45 c0 48 8b d6 48 8b c8 e8 [2] 00 00 48 89 7d d8 48 c7 c7 ff ff ff ff 4c 8d 45 40 48 89 5d d0 48 8d 55 c0 48 8d 8d 20 04 00 00 e8 ?? dd ff ff 48 81 bd 30 04 00 00 04 01 00 00 0f 87 b2 00 00 00 48 83 bd 38 04 00 00 08 48 8d 8d 20 04 00 00 48 0f 43 8d 20 04 00 00 ff 15 [2] 01 00 85 c0 0f 84 8d 00 00 00 48 8d 8d ec 04 00 00 e8 ?? e0 ff ff }
    condition:
        uint16(0) == 0x5A4D and filesize > 30KB and all of ($s*) 
}
