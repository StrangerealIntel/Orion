rule RAN_Wannahusky_Nov_2021_1 : wannahusky ransomware
{
    meta:
        description = "Detect wannahusky ransomware"
        author = "Arkbird_SOLG"
        date = "2021-11-27"
        reference = "Internal Research"
        // x86 version
        hash1 = "20e72bb205f0eba7759bafb545cd80c208fba7b4e7b64179e8ba7bab9677147f"
        hash2 = "3d35cebcf40705c23124fdc4656a7f400a316b8e96f1f9e0c187e82a9d17dca3"
        hash3 = "d6fbef917a7026b64946a571d7071075819b7ccc2cf7027352231017af14975a"
        // x64 version
        hash4 = "9538bd57ad50c41ab2655963785326085f5138b7746c41e1fd6c3b7b2a269b99"
        tlp = "white"
        adversary = "-"
    strings:
        $s1 = { 83 ec 3c 89 4d d4 39 f3 8b 3d 88 [2] 00 7c 42 c7 04 24 01 00 00 00 ff d7 c7 44 24 08 01 00 00 00 89 44 24 0c c7 44 24 04 01 00 00 00 c7 04 24 6f ?? 41 00 e8 [2] 00 00 c7 04 24 01 00 00 00 ff d7 89 04 24 e8 [2] 00 00 8d 65 f4 5b 5e 5f 5d c3 72 0f 8d 46 ff 89 1c 24 89 44 24 04 e8 [2] 00 00 8b 45 d4 8b 14 98 c7 04 24 01 00 00 00 89 55 d0 ff d7 c7 04 24 }
        $s2 = { e8 [2] ff ff 8b 15 [3] 00 [3-7] ff ff ba [2] 41 00 e8 [2] ff ff 89 da 89 c1 e8 [2] ff ff a1 [3] 00 b9 1a 00 00 00 85 c0 74 05 8b 08 83 c1 1a e8 [2] ff ff ba [2] 41 00 e8 }
        $s3 = { 8d 96 04 02 00 00 c7 44 24 08 20 00 00 00 8d 86 e4 01 00 00 89 f1 89 54 24 04 89 c2 c7 04 24 20 00 00 00 e8 [2] ff ff ba 20 00 00 00 8d 8e e4 01 00 00 83 ec 0c e8 [2] ff ff 3b 7d 0c 72 12 8b 45 0c 89 3c 24 8d }
        $x1 = { 4c 8d 6c 24 28 48 89 d3 49 39 dc 7c 40 b9 01 00 00 00 ff d7 41 b8 01 00 00 00 ba 01 00 00 00 48 8d 0d aa e8 00 00 49 89 c1 e8 8b cf 00 00 b9 01 00 00 00 ff d7 48 89 c1 e8 ac cf 00 00 90 48 83 c4 30 5b 5e 5f 5d 41 5c 41 5d 41 5e c3 72 0b 48 89 ea 4c 89 e1 e8 75 37 00 00 4e 8b 34 e6 b9 }
        $x2 = { e8 5f 6d ff ff 48 8b 15 01 a7 01 00 49 89 c1 48 85 d2 74 08 48 89 c1 e8 e9 f7 ff ff 4c 89 c9 48 8d 15 bf 41 00 00 e8 da f7 ff ff 4c 89 e2 4c 89 c9 e8 46 46 ff ff 48 8b 05 d0 a6 01 00 b9 1a 00 00 00 48 85 c0 74 07 48 8b 08 48 83 c1 1a e8 11 6d ff ff 48 8d 15 6b 41 00 00 48 89 c1 49 89 c1 e8 a0 f7 ff ff 48 8b 15 a1 a6 01 00 48 85 d2 74 08 4c 89 c9 e8 8c f7 ff ff 4c 89 c9 48 8d 15 22 41 00 00 e8 7d f7 ff ff 4c 89 c9 e8 ba ad ff ff b9 05 00 00 00 e8 d9 ad ff ff 48 8b }
        $x3 = { 4c 89 ea 48 89 f1 4d 89 f1 41 b8 20 00 00 00 48 c7 44 24 20 20 00 00 00 e8 91 ef ff ff ba 20 00 00 00 4c 89 e9 e8 d6 fa ff ff 4c 3b a4 24 b0 00 00 00 72 0b 4c 89 fa 4c 89 }
    condition:
       uint16(0) == 0x5A4D and filesize > 90KB and ( all of ($s*) or all of ($x*) )
} 
