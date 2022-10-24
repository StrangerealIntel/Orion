rule RAN_BlueSky_Aug_2022_1 : bluesky ransomware
{
    meta:
        description = "Detect the BlueSky ransomware"
        author = "Arkbird_SOLG"
        date = "2022-08-11"
        reference = "https://unit42.paloaltonetworks.com/bluesky-ransomware/"
        hash1 = "b5b105751a2bf965a6b78eeff100fe4c75282ad6f37f98b9adcd15d8c64283ec"
        hash2 = "e75717be1633b5e3602827dc3b5788ff691dd325b0eddd2d0d9ddcee29de364f"
        hash3 = "2280898cb29faf1785e782596d8029cb471537ec38352e5c17cc263f1f52b8ef"
        hash4 = "c75748dc544629a8a5d08c0d8ba7fda3508a3efdaed905ad800ffddbc8d3b8df"
        tlp = "Clear"
        adversary = "RAAS"
    strings:
        $s1 = { 83 ec 0c e8 95 98 ff ff 83 3d b0 31 41 00 00 74 23 e8 a7 38 ff ff 84 c0 0f 85 d6 00 00 00 83 3d b0 31 41 00 00 74 0d e8 b1 36 ff ff 85 c0 0f 85 c0 00 00 00 e8 94 99 ff ff 85 c0 0f 84 b3 00 00 00 c6 45 f5 00 8d 4d f5 c6 45 f6 5a c6 45 f7 70 c6 45 f8 42 c6 45 f9 08 c6 45 fa 2b c6 45 fb 09 c6 45 fc 64 c6 45 fd 09 c6 45 fe 71 c6 45 ff 63 8a 45 f6 e8 85 00 00 00 50 ff 35 88 31 41 00 68 01 00 00 80 e8 84 2e 00 00 83 c4 0c 83 f8 01 74 63 83 3d b4 31 41 00 00 74 05 e8 0e 9a ff ff e8 19 84 ff ff e8 84 9e ff ff e8 4f a7 ff ff 85 c0 74 42 e8 96 9d ff ff e8 81 96 ff ff e8 4c 9e ff ff e8 77 fa ff ff 83 3d b8 31 41 00 00 74 05 e8 29 0e 00 00 68 ff 00 00 00 68 9e 33 69 b7 68 26 57 7f 0b e8 }
        $s2 = { 51 56 8b f1 89 75 fc 80 3e 00 75 3f 53 bb 0a 00 00 00 57 8d 7e 01 8d 73 75 0f 1f 40 00 8a 07 8d 7f 01 0f b6 c0 b9 63 00 00 00 2b c8 6b c1 0b 99 f7 fe 8d 42 7f 99 f7 fe 88 57 ff 83 eb 01 75 dd 8b 45 fc 5f 5b 40 5e }
        $s3 = { 83 ec 08 6a 04 8d 45 fc c7 45 fc 00 00 00 00 50 8d 45 f8 50 ff 75 10 ff 75 0c ff 75 08 e8 3b fe ff ff 83 c4 18 83 f8 04 75 0c 39 45 f8 75 07 8b 45 fc 8b e5 5d c3 33 c0 8b }
        $s4 = { f6 80 3d 94 31 41 00 03 74 63 81 3d 9c 31 41 00 b0 1d 00 00 72 57 e8 a3 fa ff ff 84 c0 74 4e e8 fa d5 ff ff 85 c0 74 45 e8 61 fc ff ff 85 c0 74 3c e8 58 6f 00 00 50 e8 b2 d6 ff ff 83 c4 04 b9 01 00 00 00 85 c0 0f 45 f1 e8 d0 dc ff ff 85 f6 74 1b 68 ff 00 00 00 68 9e 33 69 b7 68 26 57 7f 0b e8 98 c5 ff ff 83 c4 0c 6a }
    condition:
         uint16(0) == 0x5A4D and filesize > 30KB and all of ($s*)
}
