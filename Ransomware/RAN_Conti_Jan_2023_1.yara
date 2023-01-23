rule RAN_Conti_Jan_2023_1 : ransomware conti x86 windows
{
    meta:
        description = "Detect Windows x86 version of Conti ransomware"
        author = "Arkbird_SOLG"
        date = "2023-01-23"
        reference = "Internal Research"
        hash1 = "746ac121ae024e51aa3129699cae278990cf392a661b40361d9d15b86635da94"
        hash2 = "8f11bb9536cb885bc57144392bc35e19dbc0f683d57c2c423c87a9d1c6d9d0ae"
        hash3 = "fbe45ed19fa942cc5e767acc0ef638447c4aa4b52d4900627a0a0ae71d543bee"
        hash4 = "c5ef104253ed4c066104a184ab368630027831b627c043d63170ff8f89c6a2bb"
        tlp = "Clear"
        adversary = "RAAS"
    strings:
        $s1 = { 51 8d 45 c9 8b ca 50 e8 ?? e9 ff ff 83 ec 18 33 c0 8b cc 6a ff c7 41 14 07 00 00 00 c7 41 10 00 00 00 00 50 66 89 01 8d 45 08 50 e8 [2] ff ff 8d 4d e4 e8 [2] ff ff 83 7d f8 08 8d 75 e4 6a 61 0f 43 75 e4 ba 0f 00 00 00 68 e8 10 76 01 e8 [2] fe ff 83 c4 38 6a 00 6a 00 6a 02 6a 00 6a 00 68 00 00 00 40 56 ff d0 8b f8 83 ff ff 74 57 6a 6a 68 dd 3e 7d 16 ba 0f 00 00 00 e8 [2] fe ff 83 c4 08 68 88 37 43 00 ff d0 6a 66 68 18 1e 8f 08 ba 0f 00 00 00 8b f0 e8 [2] fe ff 83 c4 08 8d 4d e0 6a 00 51 56 68 88 37 43 00 57 ff d0 6a 5b 68 72 88 52 ca ba 0f 00 00 00 e8 [2] fe ff 83 c4 08 57 ff d0 8b 45 f8 83 f8 08 72 0a 40 50 ff 75 e4 e8 ?? e9 ff ff 33 c0 c7 45 f8 07 00 }
        $s2 = { 8b d7 c1 fa 06 8b c7 83 e0 3f 6b c8 30 8b 04 95 68 48 43 00 f6 44 08 28 01 74 21 57 e8 ?? e2 ff ff 59 50 ff 15 f8 c0 42 00 85 c0 75 1d e8 ?? cb ff ff 8b f0 ff 15 54 c0 42 00 89 06 e8 ?? cb ff ff c7 00 09 00 00 00 83 ce }
        $s3 = { 0f b6 c0 2b cb 41 f7 d8 68 40 01 00 00 1b c0 23 c1 89 85 b4 fe ff ff 8d 85 bc fe ff ff 57 50 e8 ?? d3 ff ff 83 c4 0c 8d 85 bc fe ff ff 57 57 57 50 57 53 ff 15 bc c0 42 00 8b f0 8b 85 b8 fe ff ff 83 fe ff 75 2d 50 57 57 53 e8 9f fe ff ff 83 c4 10 8b f8 83 fe ff 74 07 56 ff 15 b8 }
    condition:
      uint16(0) == 0x5A4D and filesize > 80KB and all of ($s*) 
}
