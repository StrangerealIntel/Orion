rule APT_APT37_Bluelight_Dec_2022_1 : apt37 bluelight
{
   meta:
        description = "Detect the downloader agent Bluelight used by APT37 group"
        author = "Arkbird_SOLG"
        reference = "Internal Research"
        date = "2022-12-01"
        hash1 = "6f0feaba669466640fc87b77b7e64cf719644fed348b4faa015a2ffd467e8c41"
        hash2 = "ceed3bfc1f8ab82bebee93db7300cfed5bdc17fddd0401b8addbb55f48bedff3"
        hash3 = "e32c5d851cf23a6d3ecd224055619996d32210cc198ccd770494a902c788b481"
        tlp = "clear"
        adversary = "APT37"
   strings:
        $s1 = { ff 75 f0 68 34 c4 ?? 00 53 56 e8 71 fd ff ff 8b f8 83 c4 10 85 ff 0f 85 d7 00 00 00 ff 75 f0 88 86 9c 00 00 00 68 70 c4 ?? 00 53 56 e8 4f fd ff ff 83 66 18 fb 8b f8 83 c4 10 85 ff 0f 85 b1 00 00 00 ff 75 f0 68 08 c5 ?? 00 53 56 e8 2f fd ff ff 8b f8 83 c4 10 85 ff 0f 85 95 00 00 00 8b 5d f4 89 }
        $s2 = { 8b ec 81 ec 08 02 00 00 a1 5c a2 ?? 00 33 c5 89 45 fc 56 8d 85 f8 fd ff ff c7 85 f8 fd ff ff 00 02 00 00 50 8d 85 fc fd ff ff 8b f1 50 ff 15 [3] 00 8d 85 fc fd ff ff 8b ce 50 e8 ?? 46 06 00 8b 4d fc 8b c6 33 cd 5e e8 ?? a7 09 00 }
        $s3 = { 83 c4 10 8d 45 fc bb 01 00 00 80 50 56 8d 45 f8 50 6a 02 68 e4 2b ?? 00 68 00 2c ?? 00 53 ff 15 20 30 ?? 00 85 c0 75 0d 56 68 58 2c ?? 00 53 ff 15 1c 30 ?? 00 56 e8 f4 a4 0a 00 59 8b 4f 14 85 c9 74 05 }
        $s4 = { 83 e4 f8 81 ec 58 01 00 00 a1 5c a2 ?? 00 33 c4 89 84 24 54 01 00 00 56 57 8b 7d 08 8b f1 6a 00 6a 00 6a 00 6a 00 68 bc d7 ?? 00 ff 15 48 33 ?? 00 89 46 30 }
        $s5 = { 8b c2 be 00 c0 00 00 23 c6 33 c9 3b c6 0f 95 c1 85 c9 74 d0 c7 45 c8 0c 00 00 00 33 db 89 5d cc 8b c2 c1 e8 07 f7 d0 83 e0 01 89 45 d0 ff 75 0c 8d 45 c8 50 8d 45 e0 50 8d 45 e4 50 ff 15 70 32 ?? 00 85 c0 75 0f ff 15 44 32 ?? 00 50 e8 e3 }
    condition:
        uint16(0) == 0x5A4D and filesize > 300KB and all of ($s*) 
}
