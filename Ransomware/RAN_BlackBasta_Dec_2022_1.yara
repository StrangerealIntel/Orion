rule RAN_BlackBasta_Dec_2022_1 : blackbasta ransomware
{
   meta:
        description = "Detect the BlackBasta ransomware (DLL v2)"
        author = "Arkbird_SOLG"
        reference = "https://www.zscaler.com/blogs/security-research/back-black-basta"
        date = "2022-12-01"
        hash1 = "51eb749d6cbd08baf9d43c2f83abd9d4d86eb5206f62ba43b768251a98ce9d3e"
        hash2 = "ab24df3877345cfab2c946d8a714f1ef17fe18c6744034b44ec0c83a3b613195"
        hash3 = "07117c02a09410f47a326b52c7f17407e63ba5e6ff97277446efc75b862d2799"
        tlp = "clear"
        adversary = "RAAS"
   strings:
        $s1 = { 8b ec 6a ff 68 [2] 09 10 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 1c c7 45 d8 00 00 00 00 c7 45 e8 00 00 00 00 c7 45 ec 00 00 00 00 68 [3] 10 c7 45 e8 00 00 00 00 c7 45 ec 0f 00 00 00 c6 45 d8 00 e8 a4 ?? 07 00 83 c4 04 8d 4d d8 50 68 [3] 10 e8 [2] 00 00 c7 45 fc 00 00 00 00 8d 45 f3 50 8d 4d f0 51 8d 55 d8 b9 [2] 0c 10 52 e8 [2] 00 00 c7 45 fc ff ff ff ff 8d 45 d8 68 [2] 00 10 6a 01 6a 18 50 e8 [2] 06 00 68 [2] 09 10 e8 [2] 06 00 8b 4d f4 83 c4 04 64 89 0d 00 00 00 00 } 
        $s2 = { 51 52 e8 ?? ba 05 00 83 c4 08 6a 00 68 80 00 00 00 6a 02 33 c0 c7 45 dc 00 00 00 00 83 7d c8 08 6a 00 66 89 45 cc 8d 45 b4 0f 43 45 b4 6a 00 68 00 00 00 c0 50 c7 45 e0 07 00 00 00 ff 15 [3] 10 8b f8 83 ff ff 74 15 6a 00 6a 00 68 43 04 00 00 68 [2] 0c 10 57 ff 15 [3] 10 57 ff 15 [3] 10 83 e6 fd 89 75 f0 c6 45 fc 00 8b 4d c8 5f 5e 5b 83 f9 08 72 2e 8b 55 b4 8d 0c 4d 02 00 00 00 8b }
        $s3 = { c6 45 fc ?? c7 [2-5] 00 00 00 00 c7 [2-5] 00 00 00 00 c7 [2-5] 00 00 00 00 68 [7-10] 00 00 00 00 c7 }
        $s4 = { c7 45 ?? 00 00 00 00 [0-3] c7 45 ?? 00 00 00 00 c7 45 ?? 00 00 00 00 68 [3] 10 c7 45 ?? 00 00 00 00 c7 45 ?? 0f 00 00 00 c6 45 ?? 00 }
    condition:
        uint16(0) == 0x5A4D and filesize > 200KB and all of ($s*) 
}
