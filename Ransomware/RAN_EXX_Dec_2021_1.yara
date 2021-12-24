rule RAN_EXX_Dec_2021_1 
{
   meta:
        description = "Detect EXX ransomware"
        author = "Arkbird_SOLG"
        reference = "Internal Research"
        date = "2021-12-23"
        hash1 = "c0f07b493cc32ffcbb4ca1ca92f5752c4040b1d0be7b69981c22a27f69cfb890"
        hash2 = "fa28436aaf459d16215dd2d96ea5756c09198216c52d90a7a20abde4e826909b"
        tlp = "white"
        adversary = "EXX"
   strings:
        $s1 = { 68 00 00 00 f0 6a 01 53 53 8d 45 f8 50 ff 15 04 60 ?? 00 85 c0 74 6a 8b 45 f8 85 c0 74 63 8d 4d fc 51 53 53 68 03 80 00 00 50 ff 15 08 60 ?? 00 85 c0 74 4d 8b 45 fc 85 c0 74 54 8b 55 08 53 52 56 50 ff 15 10 60 ?? 00 85 c0 74 35 8b 55 fc 8b 35 00 60 ?? 00 53 8d 45 f0 50 8d 4d f4 51 6a 04 52 ff d6 85 }
        $s2 = { e8 6f 32 00 00 8b 3d 44 61 ?? 00 68 84 01 00 00 6a 08 c7 45 fc 04 01 00 00 ff d7 50 ff 15 3c 61 ?? 00 8b f0 85 f6 74 51 53 8b 1d 18 61 ?? 00 8d 45 fc 50 56 ff d3 85 c0 75 3e ff 15 d4 60 ?? 00 83 f8 6f 75 33 8b 45 fc 85 c0 75 0f 56 50 ff d7 50 ff }
        $s3 = { 68 0c 04 00 00 8d 8d e8 fb ff ff 57 51 c7 05 f0 4b ?? 00 50 31 ?? 00 89 bd e4 fb ff ff e8 d5 f5 00 00 83 c4 0c 68 d8 39 ?? 00 68 04 01 00 00 89 7d f8 ff 15 ac 60 ?? 00 85 c0 0f 84 41 01 00 00 33 c0 b9 5c 00 00 00 66 39 88 d8 39 ?? 00 75 09 33 d2 66 89 90 d8 39 ?? 00 83 c0 02 3d 08 02 00 00 72 e4 66 39 3d d8 39 ?? 00 8b 3d 34 61 ?? 00 53 8b 1d d8 60 ?? 00 56 be d8 39 ?? 00 74 67 8d 45 fc 50 6a 00 56 68 f0 1c ?? 00 6a 00 6a 00 c7 45 fc 00 00 00 00 ff d7 85 c0 75 1d 68 e8 03 00 00 ff d3 8d 4d fc 51 6a 00 56 68 f0 1c ?? 00 6a 00 6a 00 ff }
        $s4 = { 56 ff 15 00 62 ?? 00 a1 fc 0e ?? 00 8b 1d 28 62 ?? 00 50 56 ff d3 0f 31 50 8d 4d ac 68 88 9b ?? 00 51 ff 15 44 62 ?? 00 83 c4 0c 8d 55 ac 52 56 ff d3 68 80 00 00 00 57 ff 15 ec 60 ?? 00 6a 00 68 80 00 00 08 6a 03 6a 00 6a 00 68 00 00 00 c0 57 ff 15 60 60 ?? 00 8b d8 83 fb ff 0f 84 c2 01 00 00 33 c0 89 45 f0 89 45 f4 8d 45 f0 50 53 ff 15 54 61 ?? 00 8b 4d f0 8b 45 f4 8b d1 0b d0 0f 84 78 01 00 00 85 c0 0f 8c 70 01 00 00 7f 09 83 }
    condition:
         uint16(0) == 0x5A4D and filesize > 80KB and all of ($s*) 
}