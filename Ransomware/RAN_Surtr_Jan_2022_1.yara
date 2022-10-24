rule RAN_Surtr_Jan_2022_1
{
    meta:
        description = "Detect Surtr ransomware"
        author = "Arkbird_SOLG"
        date = "2021-01-01"
        reference = "Internal Research"
        hash1 = "40e5bb0526169c02126ffa60a09041e5e5453a24b26bc837036748b150fa3fae"
        hash2 = "7dfcbf301686c56d31874642114b1c6ff8f78dfd76f4b88c2f056b7aff8fb19b"
        tlp = "Clear"
        adversary = "-"
    strings:
        $s1 = { 4c 8d 35 15 27 11 00 c7 44 24 20 00 00 00 f0 41 b9 18 00 00 00 4c 8d 05 a0 29 11 00 33 d2 48 8d 4d 00 ff 15 24 6b 10 00 8b d8 85 c0 74 4b 4c 8d 35 ff 26 11 00 4c 8d 4d f8 ba 10 66 00 00 41 b8 01 00 00 00 48 8b 4d 00 ff 15 0e 6b 10 00 8b d8 85 c0 74 25 4c 8d 35 d1 29 11 00 c7 45 d0 01 00 00 00 45 33 c9 4c 8d 45 d0 41 8d 51 04 48 8b 4d f8 ff 15 c5 6a 10 00 8b d8 48 8d 45 c0 48 89 44 24 28 48 89 7c 24 20 45 33 c9 33 d2 45 8d 41 08 48 8b 4d f8 ff 15 d2 6a 10 00 85 c0 75 0c 48 8d 0d 9f 29 11 00 e8 52 f2 ff ff 8b 4d c0 e8 5a 09 0f 00 4c 8b e8 48 8d 45 c0 48 89 44 24 28 4c 89 6c 24 20 45 33 c9 33 d2 45 8d 41 08 48 8b 4d f8 ff 15 96 6a 10 00 85 }
        $s2 = { c7 85 90 02 00 00 01 01 00 00 48 8d 95 90 02 00 00 48 8d 8d 10 03 00 00 ff 15 f2 e9 0f 00 48 8d 85 10 03 00 00 49 c7 c7 ff ff ff ff 4d 8b c7 49 ff c0 42 38 34 00 75 f7 48 8d 95 10 03 00 00 4c 8d 2d f2 a3 11 00 49 8b cd e8 1a e9 0d 00 c7 85 90 02 00 00 01 01 00 00 48 8d 95 90 02 00 00 48 8d 8d 10 03 00 00 ff 15 a4 ea 0f 00 48 8d 85 10 03 00 00 }
        $s3 = { 4c 8d 05 a1 83 03 00 33 d2 33 c9 ff 15 1f 37 02 00 48 89 45 c8 48 8b 55 e8 4c 8b 45 f0 49 8b c8 48 2b ca 48 83 f9 0b 72 33 48 8d 4a 0b 48 89 4d e8 48 8d 5d d8 49 83 f8 10 48 0f 43 5d d8 48 03 da 41 b8 0b 00 00 00 }
        $s4 = { ff 15 c3 0b 10 00 85 c0 74 65 48 8d 0d 38 4b 11 00 e8 4b 8f ff ff 33 f6 49 89 36 49 89 76 10 49 c7 46 18 0f 00 00 00 41 88 36 44 8d 46 1d 48 8d 15 dc 4a 11 00 49 8b ce e8 e4 06 0e 00 90 48 8b 57 18 48 83 fa 10 0f 82 fa fe ff ff 48 ff c2 48 81 fa 00 10 00 00 48 8b }
        $s5 = { 48 89 74 24 30 89 74 24 28 c7 44 24 20 03 00 00 00 45 33 c9 33 d2 45 8d 41 03 48 8d 0d 1d 0c 03 00 ff 15 9f 29 02 00 48 89 74 24 38 48 8d 4d f8 48 89 4c 24 30 41 be 18 00 00 00 44 89 74 24 28 48 8d 4d 50 48 89 4c 24 20 45 33 c9 45 33 c0 ba 00 00 07 00 48 8b c8 ff 15 91 29 02 00 8b 45 64 8b 4d 60 48 0f af c1 8b 4d 5c 48 0f af c1 48 0f af 45 50 48 99 81 e2 ff ff ff 3f 48 03 c2 48 c1 f8 1e 83 f8 28 73 07 66 }
    condition:
       uint16(0) == 0x5A4D and filesize > 300KB and all of ($s*) 
}  
