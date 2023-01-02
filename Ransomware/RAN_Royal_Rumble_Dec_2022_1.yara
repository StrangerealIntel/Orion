rule RAN_Royal_Rumble_Dec_2022_1 : royal_rumble ransomware x86
{
   meta:
        description = "Detect the Royal Rumble ransomware (x86)"
        author = "Arkbird_SOLG"
        reference = "Internal Research"
        date = "2022-12-20"
        hash1 = "250bcbfa58da3e713b4ca12edef4dc06358e8986cad15928aa30c44fe4596488"
        hash2 = "de025f921dd477c127fba971b9f90accfb58b117274ba1afb1aaf2222823b6ac"
        hash3 = "47c00ac29bbaee921496ef957adaf5f8b031121ef0607937b003b6ab2a895a12"
        tlp = "Clear"
        adversary = "-"
   strings:
        $s1 = { 83 c4 04 8d 85 ?? ef ff ff 83 bd ?? ef ff ff 08 0f 43 85 ?? ef ff ff 6a 00 6a 00 6a 02 6a 00 6a 00 68 00 00 00 40 50 ff 15 [2] 59 00 8b f0 83 fe ff 74 ?? 68 00 10 00 00 8d 85 ?? ef ff ff 6a 00 50 e8 [2] 12 00 }
        $s2 = { 68 00 02 00 00 8d 84 24 dc 47 00 00 6a 00 50 e8 [2] 12 00 83 c4 0c 8d 84 24 d8 47 00 00 68 [3] 00 50 ff 15 [2] 59 00 83 c4 08 c7 44 24 40 44 00 00 00 8d 44 24 20 0f 57 c0 66 0f 13 44 24 44 66 0f 13 44 24 4c 50 8d 44 24 44 66 0f 13 44 24 58 50 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 8d 84 24 f8 47 00 00 66 0f 13 44 24 7c 50 68 [3] 00 66 0f 13 84 24 8c 00 00 00 66 0f 13 84 24 94 00 00 00 66 0f 13 84 24 9c 00 00 00 66 0f 13 84 24 a4 00 00 00 0f 29 44 24 48 ff 15 44 }
        $s3 = { 68 [2] 60 00 ff 15 54 ?? 59 00 50 68 [2] 60 00 57 e8 [2] 00 00 [10-13] 00 00 8b d8 57 89 [5-6] 00 00 83 c4 ?? 85 db 0f 84 ?? 01 00 00 68 00 a0 0f 00 e8 [2] 12 00 8b d8 83 c4 04 89 }
        $s4 = { 50 68 [2] 59 00 57 68 [3] 00 56 b3 01 e8 [2] fb ff ff 74 24 2c c7 44 24 2c 00 00 00 00 e8 [2] f9 ff 8b 4c 24 2c 83 c4 1c 3b c8 7d 5e 8b 7c 24 14 84 db 75 14 68 [2] 5b 00 56 e8 [2] f9 ff 8b 4c 24 18 83 c4 08 eb 02 32 db 6a 00 51 57 e8 [2] f9 ff 83 c4 08 50 8d 44 24 28 6a 50 50 e8 [2] fb ff 8d 44 24 30 50 56 e8 [2] f9 ff ff 44 24 28 57 e8 }
    condition:
        uint16(0) == 0x5A4D and filesize > 150KB and all of ($s*)
}
