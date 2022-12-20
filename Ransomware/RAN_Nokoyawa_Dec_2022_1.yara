rule RAN_Nokoyawa_Dec_2022_1
{
   meta:
        description = "Detect the rust variant of Nokoyawa ransomware (x64)"
        author = "Arkbird_SOLG"
        reference = "https://www.zscaler.com/blogs/security-research/nokoyawa-ransomware-rust-or-bust"
        date = "2022-12-20"
        hash1 = "259f9ec10642442667a40bf78f03af2fc6d653443cce7062636eb750331657c4"
        hash2 = "7095beafff5837070a89407c1bf3c6acf8221ed786e0697f6c578d4c3de0efd6"
        hash3 = "47c00ac29bbaee921496ef957adaf5f8b031121ef0607937b003b6ab2a895a12"
        tlp = "Clear"
        adversary = "-"
   strings:
        $s1 = { 56 57 55 53 48 81 ec d8 00 00 00 49 89 d6 48 89 8c 24 b8 00 00 00 48 c7 44 24 20 06 00 00 00 4c 8d 0d [3] 00 48 8d 4c 24 48 4c 89 44 24 28 e8 [2] 00 00 48 83 7c 24 68 00 0f 84 41 01 00 00 4c 89 b4 24 b0 00 00 00 48 8b b4 24 a0 00 00 00 4c 8b 64 24 48 48 8b 54 24 50 4c 8b 7c 24 58 4c 8b 74 24 60 48 83 fe ff 0f 84 6a 01 00 00 4c 8b ac 24 90 00 00 00 4b 8d 0c 2e 48 83 c1 ff 48 39 }
        $s2 = { 48 83 ec 38 48 8d 6c 24 30 48 c7 45 00 fe ff ff ff 48 8b 1d [2] 04 00 48 85 db 74 48 48 89 d9 ba ff ff ff ff 45 31 c0 e8 [2] 01 00 48 8b 05 [2] 04 00 48 85 c0 75 1c 48 8d 0d [3] 00 e8 [2] 01 00 48 89 05 [2] 04 00 48 85 c0 0f 84 12 01 00 00 80 3d [2] 04 00 00 74 44 31 ff e9 0f 01 00 00 4c 8d 05 [3] 00 31 c9 31 d2 e8 [2] 01 00 }
        $s3 = { 48 8b 45 20 c7 04 10 2e 74 78 74 48 83 c2 04 48 89 55 e0 0f 28 45 20 0f 29 45 d0 c6 45 3f 01 48 8d 0d [3] 00 4c 8d 05 [3] 00 ba 0c 00 00 00 e8 [2] 00 00 48 85 c0 75 07 48 8b 05 [3] 00 c6 45 3f 01 48 89 c1 e8 [2] 00 00 48 85 c0 0f 84 02 01 00 00 49 89 d0 c6 45 3f 01 48 8d 4d f0 48 89 c2 e8 [2] 00 00 48 83 7d f0 }
        $s4 = { 48 81 ec c8 00 00 00 48 8d ac 24 80 00 00 00 48 c7 45 40 fe ff ff ff 48 89 ca 48 8d 4d f0 e8 [2] 02 00 c6 45 3e 01 48 8d 0d [3] 00 4c 8d 05 [3] 00 ba 09 00 00 00 e8 [2] 00 00 48 85 c0 75 07 48 8b 05 [3] 00 c6 45 3e 01 48 89 c1 e8 [2] 00 00 48 89 c7 48 85 c0 0f 84 a4 01 00 00 48 89 d6 48 8b 45 f8 48 8b 5d 00 48 29 }
    condition:
        uint16(0) == 0x5A4D and filesize > 80KB and all of ($s*)
} 
