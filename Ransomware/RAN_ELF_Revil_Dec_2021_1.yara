rule RAN_ELF_Revil_Dec_2021_1 
{
   meta:
        description = "Detect ELF version of Revil ransomware"
        author = "Arkbird_SOLG"
        reference = "Internal Research"
        date = "2021-12-23"
        hash1 = "a322b230a3451fd11dcfe72af4da1df07183d6aaf1ab9e062f0e6b14cf6d23cd"
        hash2 = "f864922f947a6bb7d894245b53795b54b9378c0f7633c521240488e86f60c2c5"
        hash3 = "ea1872b2835128e3cb49a0bc27e4727ca33c4e6eba1e80422db19b505f965bc4"
        tlp = "white"
        adversary = "Sodinokibi"
   strings:
        $s1 = { 48 83 ec 30 48 89 7d e8 48 89 75 e0 48 89 55 d8 48 8b 45 e8 48 83 c0 28 48 89 c7 e8 [2] ff ff eb 1b 48 8b 45 e8 48 8d 50 28 48 8b 45 e8 48 83 e8 80 48 89 d6 48 89 c7 e8 [2] ff ff 48 8b 45 e8 48 89 c7 e8 17 ff ff ff 85 c0 74 16 48 8b 45 e8 8b 40 24 85 c0 75 0b 48 8b 45 e8 8b 40 20 85 c0 74 bf 48 8b 45 e8 8b 40 24 85 c0 75 0b 48 8b 45 e8 8b 40 20 85 c0 74 1a 48 8b 45 e8 48 83 c0 28 48 89 c7 e8 [2] ff ff b8 ff ff ff ff e9 9c 00 00 00 48 8b 45 e8 48 89 c7 e8 a1 fe ff ff 89 45 fc 48 8b 45 e8 48 8b 48 10 48 8b 45 e8 8b 40 1c 48 63 d0 48 89 d0 48 01 c0 48 01 d0 48 c1 e0 03 48 01 c8 48 89 45 f0 48 8b 45 f0 48 8b 55 e0 48 89 10 48 8b 45 d8 48 89 c7 e8 e1 fe ff ff 48 8b 55 f0 48 89 42 08 48 8b 45 e8 8b 40 1c 8d 50 01 48 8b 45 e8 8b 48 04 89 d0 99 f7 f9 48 8b 45 e8 89 50 1c }
        $s2 = { 48 83 ec 20 48 89 7d e8 89 f0 66 89 45 e4 48 c7 45 f8 00 00 00 00 be 00 00 00 00 bf [2] 41 00 b8 00 00 00 00 e8 [2] ff ff 89 45 f4 83 7d f4 ff 75 16 be 1e 00 00 00 bf [2] 41 00 b8 00 00 00 00 e8 [2] ff ff eb 59 0f b7 55 e4 48 8b 4d e8 8b 45 f4 48 89 ce 89 c7 e8 [2] ff ff 48 89 45 f8 48 83 7d f8 ff 75 16 be 26 00 00 00 bf [2] 41 00 b8 00 00 00 00 e8 [2] ff ff eb 23 0f b7 45 e4 48 3b 45 f8 76 19 0f b7 45 e4 48 8b 55 f8 89 c6 bf [2] 41 00 b8 00 00 00 00 e8 [2] ff ff 8b 45 f4 89 c7 e8 [2] ff ff b8 01 }
        $s3 = { 65 73 78 63 6c 69 20 2d 2d 66 6f 72 6d 61 74 74 65 72 3d 63 73 76 20 2d 2d 66 6f 72 6d 61 74 2d 70 61 72 61 6d 3d 66 69 65 6c 64 73 3d 3d 22 57 6f 72 6c 64 49 44 2c 44 69 73 70 6c 61 79 4e 61 6d 65 22 20 76 6d 20 70 72 6f 63 65 73 73 20 6c 69 73 74 20 7c 20 61 77 6b 20 2d 46 20 22 5c 22 2a 2c 5c 22 2a 22 20 27 7b 73 79 73 74 65 6d 28 22 65 73 78 63 6c 69 20 76 6d 20 70 72 6f 63 65 73 73 20 6b 69 6c 6c 20 2d 2d 74 79 70 65 3d 66 6f 72 63 65 20 2d 2d 77 6f 72 6c 64 2d 69 64 3d 22 20 24 31 29 7d }
        $s4 = { 7b 22 76 65 72 22 3a 25 64 2c 22 70 69 64 22 3a 22 25 73 22 2c 22 73 75 62 22 3a 22 25 73 22 2c 22 70 6b 22 3a 22 25 73 22 2c 22 75 69 64 22 3a 22 25 73 22 2c 22 73 6b 22 3a 22 25 73 22 2c 22 6f 73 22 3a 22 25 73 22 2c 22 65 78 74 22 3a 22 25 73 22 7d }
    condition:
        uint32(0) == 0x464C457F and filesize > 30KB and all of ($s*) 
}

