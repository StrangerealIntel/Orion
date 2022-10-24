rule RAN_ELF_ALPHV_Dec_2021_1
{
    meta:
        description = "Detect the ELF version of ALPHV ransomware"
        author = "Arkbird_SOLG"
        date = "2021-12-20"
        reference = "Internal Research"
        hash1 = "5121f08cf8614a65d7a86c2f462c0694c132e2877a7f54ab7fcefd7ee5235a42"
        hash2 = "f8c08d00ff6e8c6adb1a93cd133b19302d0b651afd73ccb54e3b6ac6c60d99c6"
        tlp = "Clear"
        adversary = "BlackCat"
    strings:
        $s1 = { 5b 89 ce c7 44 24 14 00 00 00 00 c7 44 24 10 00 00 00 00 81 c3 f5 bd 06 00 83 ec 08 8d 44 24 18 68 00 00 08 00 50 e8 d6 28 ea ff 83 c4 10 83 f8 ff 74 28 8b 44 24 10 83 f8 ff 89 44 24 0c 74 39 8b 4c 24 14 83 f9 ff 89 4c 24 0c 74 2c 89 46 04 89 4e 08 c7 06 00 00 00 00 eb 17 e8 81 28 ea ff 8b 00 c7 46 04 00 00 00 00 89 46 08 c7 06 01 00 00 00 83 c4 30 5e 5f 5b c3 c7 44 24 18 00 00 00 00 83 ec 04 8d 83 5c f1 ff ff 8d 74 24 1c 8d bb d8 ee fa ff 8d 54 24 10 b9 01 }
        $s2 = { 83 3e 01 8b 39 b8 1c 00 00 00 bd 10 00 00 00 0f 44 e8 83 c6 04 83 ec 04 55 56 57 e8 27 ad e9 ff 83 c4 10 83 f8 ff 74 02 eb 39 89 7c 24 08 66 2e 0f 1f 84 00 00 00 00 00 0f 1f }
        $s3 = { 80 3d d0 07 3c 00 00 48 89 e5 41 54 53 75 62 48 83 3d c8 03 3c 00 00 74 0c 48 8b 3d 8f 06 3c 00 e8 52 ff ff ff 48 8d 1d b3 54 3b 00 4c 8d 25 a4 54 3b 00 48 8b 05 a5 07 3c 00 4c 29 e3 48 c1 fb 03 48 83 eb 01 48 39 d8 73 20 0f 1f 44 00 00 48 83 c0 01 48 89 05 85 07 3c 00 41 ff 14 c4 48 8b 05 7a 07 3c 00 48 39 d8 72 e5 c6 05 66 07 3c 00 01 5b }
        $s4 = { 49 89 ff 48 8b 46 10 48 8d 48 ff 48 83 e1 f7 48 83 c1 09 48 83 f8 01 ba 01 00 00 00 48 0f 43 d0 41 bc 09 00 00 00 4c 0f 43 e1 48 83 fa 09 bb 08 00 00 00 48 0f 43 da 48 83 c3 0f 48 83 e3 f0 48 8b 3c 1f 4d 01 fc 49 01 dc ff 15 96 e5 3b 00 49 8b 3c 1f ff 15 f4 e2 3b 00 4c 89 e7 41 ff 16 49 83 ff ff 74 69 f0 49 83 6f 08 01 75 61 49 8b 46 08 49 8b 4e 10 48 85 c9 ba 01 00 00 00 48 0f 45 d1 48 01 d0 48 83 c0 ff 48 89 d1 48 f7 d9 48 21 c1 48 83 fa 09 b8 08 00 00 00 48 0f 43 c2 48 01 c1 48 83 c1 08 48 89 c2 48 f7 da 48 21 d1 48 01 c8 }
        $s5 = { 3f 61 63 63 65 73 73 2d 6b 65 79 3d 24 7b 41 43 43 45 53 53 5f 4b 45 59 7d 22 2c 22 6e 6f 74 65 5f 73 68 6f 72 74 5f 74 65 78 74 22 }
    condition:
      uint32(0) == 0x464C457F and filesize > 90KB and 3 of ($s*) 
}