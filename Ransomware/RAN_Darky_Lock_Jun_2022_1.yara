rule RAN_Darky_Lock_Jun_2022_1 : darkylock ransomware
{
   meta:
        description = "Detect the Darky Lock ransomware"
        author = "Arkbird_SOLG"
        reference = "Internal Research"
        date = "2022-07-15"
        hash1 = "9e67a1c67e3768e7f1f5fc4509119d1999722c6fc349a6398c9b72819e6ebe8d"
        hash2 = "393a7a313548a4edc025fb47c6c8e614ecc2b41db880ecb59f20cf238e9a864c"
        hash3 = "fc28d2eaee1fd3416fe3e0cd4669df3ac178c577e3a8c386b1c34c3146afb8d6"
        tlp = "White"
        adversary = "RAAS"
   strings:
        $s1 = { 81 ec 90 00 00 00 56 57 c7 45 f8 00 00 00 00 ff 15 2c 50 41 00 89 45 e4 c7 45 e0 30 75 00 00 68 3f 00 0f 00 6a 00 6a 00 ff 15 04 50 41 00 89 45 e8 83 7d e8 00 0f 84 f5 01 00 00 c7 45 f0 00 00 00 00 eb 09 8b 45 f0 83 c0 01 89 45 f0 83 7d f0 2c 0f 83 cf 01 00 00 6a 2c 8b 4d f0 8b 14 8d 00 40 41 00 52 8b 45 e8 50 ff 15 20 50 41 00 89 45 fc }
        $s2 = { 83 7d f8 00 0f 85 e6 00 00 00 83 7d f4 00 0f 85 dc 00 00 00 68 1c 3c 40 00 6a 00 68 01 00 1f 00 ff 15 c4 50 41 00 85 c0 75 11 68 40 3c 40 00 6a 00 6a 00 ff 15 98 50 41 00 }
        $s3 = { ff 15 04 51 41 00 89 45 c0 83 7d c0 00 74 3f b8 41 00 00 00 66 89 45 f0 eb 0c 66 8b 4d f0 66 83 c1 01 66 89 4d f0 0f b7 55 f0 83 fa 5a 7f 1f 8b 45 c0 83 e0 01 74 0d 0f b7 4d f0 51 e8 b9 fa ff ff 83 }
        $s4 = { 83 ec 10 c7 45 f4 ff ff ff ff c7 45 f8 00 40 00 00 8d 45 f0 50 8b 4d 08 51 6a 13 6a 00 6a 02 e8 1e 89 00 00 85 c0 0f 85 9d 00 00 00 8b 55 f8 52 e8 f8 84 00 00 83 c4 04 89 45 08 83 7d 08 00 74 7f 8d 45 f8 50 8b 4d 08 51 8d 55 f4 52 8b 45 f0 50 }
   condition:
       uint16(0) == 0x5A4D and filesize > 50KB and all of ($s*)
}
