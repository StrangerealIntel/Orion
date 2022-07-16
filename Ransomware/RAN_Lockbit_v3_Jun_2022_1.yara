rule RAN_Lockbit_v3_Jun_2022_1 : lockbit ransomware
{
   meta:
        description = "Detect the lockbit ransomware"
        author = "Arkbird_SOLG"
        reference = "https://twitter.com/vxunderground/status/1543661557883740161"
        date = "2022-07-04"
        hash1 = "80e8defa5377018b093b5b90de0f2957f7062144c83a09a56bba1fe4eda932ce"
        hash2 = "a56b41a6023f828cccaaef470874571d169fdb8f683a75edd430fbd31a2c3f6e"
        hash3 = "391a97a2fe6beb675fe350eb3ca0bc3a995fda43d02a7a6046cd48f042052de5"
        tlp = "White"
        adversary = "RAAS"
   strings:
        $s1 = { b8 fc fd fe ff b9 40 00 00 00 8b 5d 10 89 44 8b fc 2d 04 04 04 04 49 75 f4 8b 7d 0c be 40 00 00 00 33 db 55 8b 6d 10 8b c1 33 d2 f7 f6 8a c1 8a 14 17 02 54 05 00 02 d3 8a 5c 15 00 8a 54 1d 00 86 54 05 00 88 54 1d 00 41 81 f9 00 03 00 00 75 d6 5d 33 c9 8b 7d 08 be 20 00 00 00 55 8b 6d 10 8b c1 33 d2 f7 f6 8a c1 8a 14 17 02 54 05 00 02 d3 8a 5c 15 00 8a 54 1d 00 86 54 05 00 88 54 1d 00 41 81 f9 00 03 00 00 75 d6 5d 33 c9 8b 7d 0c be 40 00 00 00 55 8b 6d 10 8b c1 33 d2 f7 f6 8a c1 8a 14 17 02 54 05 00 02 d3 8a 5c 15 00 8a 54 1d 00 86 54 05 00 88 54 1d 00 41 81 f9 00 03 }
        $s2 = { 81 ec 7c 03 00 00 53 56 57 8d 9d 84 fc ff ff b9 00 c2 eb 0b e2 fe e8 c6 02 00 00 53 50 e8 23 02 00 00 85 c0 74 79 53 8d 45 a0 50 e8 c1 02 00 00 8d 85 8c fe ff ff 50 8d 45 c0 50 8d 45 a0 50 e8 01 03 00 00 89 45 9c e8 85 02 00 00 8b d8 8b 5b 08 8b 73 3c 03 f3 0f b7 7e 06 8d b6 f8 00 00 00 6a 00 8d 06 50 e8 7f 00 00 00 3d 75 80 91 76 74 0e 3d 1b a4 04 00 74 07 3d 9b b4 84 0b 75 18 8b 4e 0c 03 cb ff 75 9c 8d 85 8c fe ff ff 50 ff 76 10 51 e8 82 03 00 00 83 }
        $s3 = { 66 ad 66 85 c0 75 05 e9 8a 00 00 00 66 83 f8 41 72 0c 66 83 f8 46 77 06 66 83 e8 37 eb 26 66 83 f8 61 72 0c 66 83 f8 66 77 06 66 83 e8 57 eb 14 66 83 f8 30 72 0c 66 83 f8 39 77 06 66 83 e8 30 eb 02 eb bc 0f b6 c8 c1 e1 04 66 ad 66 85 c0 75 02 eb 43 66 83 f8 41 72 0c 66 83 f8 46 77 06 66 83 e8 37 eb 29 66 83 f8 61 72 0c 66 83 f8 66 77 06 66 83 e8 57 eb 17 66 83 f8 30 72 0c 66 83 f8 39 77 06 66 83 e8 30 eb 05 e9 72 ff ff ff 32 c1 aa e9 6a }
   condition:
       uint16(0) == 0x5A4D and filesize > 80KB and all of ($s*)
}

