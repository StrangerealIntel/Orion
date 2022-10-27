rule RAN_Black_Basta_Apr_2022_1 : ransomware blackbasta
{
   meta:
        description = "Detect black basta ransomware"
        author = "Arkbird_SOLG"
        reference = "https://twitter.com/MarceloRivero/status/1519398885193654273"
        date = "2022-04-27"
        hash1 = "7883f01096db9bcf090c2317749b6873036c27ba92451b212b8645770e1f0b8a"
        hash2 = "5d2204f3a20e163120f52a2e3595db19890050b2faa96c6cba6b094b0a52b0aa"
        tlp = "Clear"
        adversary = "RAAS"
   strings:
        $s1 = { 81 ec ?? 00 00 00 a1 [2] 48 00 33 c5 89 45 f0 [0-2] 50 8d 45 f4 64 a3 00 00 00 00 [0-3] c7 45 fc 00 00 00 00 8d [2] ff ff ff }
        $s2 = { 6a 00 68 00 00 20 02 6a 03 6a 00 6a 07 6a 00 50 ff 15 [2] 46 00 8b f8 89 7d 0c c7 45 fc 01 00 00 00 83 ff ff 75 3b ff 15 [2] 46 00 8b 4d 10 89 01 8b 45 08 c7 41 04 [2] 48 00 c7 00 00 00 00 00 c7 45 f0 01 00 00 00 c6 45 fc 00 89 7d 0c 8b 4d f4 64 89 0d 00 00 00 00 59 5f 5e 5b 8b e5 5d c3 68 00 40 00 00 6a 01 e8 [2] 02 00 8b d8 83 c4 08 89 5d ec c6 45 fc 02 8d 45 e8 6a 00 50 68 00 40 00 00 53 6a 00 6a 00 68 a8 00 09 00 57 ff 15 [2] 46 00 85 c0 74 15 8b 75 08 c7 45 ec 00 00 00 00 c7 45 f0 01 00 00 00 89 1e eb 33 ff 15 [2] 46 00 8b 4d 10 8b 75 08 c7 45 f0 01 00 00 00 89 01 c7 41 04 [2] 48 00 c7 06 00 00 00 00 c6 45 }
        $s3 = { 6a 02 8d 45 08 50 8d 4d ?? e8 [2] ff ff c6 45 fc 06 50 8d 8d [2] ff ff e8 [2] 00 00 c6 45 fc 07 c6 45 fc 03 8d 4d ?? e8 [2] 00 00 6a 02 8d 45 08 50 8d 4d ?? e8 [2] ff ff c6 45 fc 08 83 ec 18 8b cc 89 a5 [2] ff ff 51 8b c8 e8 [2] ff ff c6 45 fc 09 c6 45 fc 08 e8 [2] ff ff 83 c4 18 c6 45 fc 0a c6 45 fc 03 8d 4d ?? e8 [2] 00 00 e8 [2] 01 00 8d 3c 40 3b 3d [2] 48 00 0f 42 3d [2] 48 00 89 }
        $s4 = { 57 68 a0 0f 00 00 68 [2] 48 00 ff 15 [2] 46 00 68 [3] 00 ff 15 [2] 46 00 8b f0 85 f6 75 11 68 [3] 00 ff 15 [2] 46 00 8b f0 85 f6 74 46 68 [3] 00 56 ff 15 [2] 46 00 68 [3] 00 56 8b f8 ff 15 [2] 46 00 85 ff 74 12 85 c0 74 0e 89 3d [2] 48 00 a3 [2] 48 00 5f 5e c3 33 c0 50 50 6a 01 50 ff 15 [2] 46 00 a3 } 
   condition: 
        uint16(0) == 0x5A4D and filesize > 25KB and all of ($s*) 
}
