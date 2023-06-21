rule APT_APT15_Graphican_Jun_2023_1 : apt apt15 backdoor graphican 
{
   meta:
        description = "Detect the Graphican backdoor used by the apt15 group"
        author = "Arkbird_SOLG"
        reference = "https://www.microsoft.com/security/blog/2022/07/27/untangling-knotweed-european-private-sector-offensive-actor-using-0-day-exploits/"
        date = "2023-06-21"
        hash1 = "4b78b1a3c162023f0c14498541cb6ae143fb01d8b50d6aa13ac302a84553e2d5"
        hash2 = "a78cc475c1875186dcd1908b55c2eeaf1bcd59dedaff920f262f12a3a9e9bfa8"
        hash3 = "02e8ea9a58c13f216bdae478f9f007e20b45217742d0fbe47f66173f1b195ef5"
        tlp = "Clear"
        adversary = "APT15"
   strings:
        $s1 = { 33 db bf 0a 02 00 00 b8 [3] 00 8d 75 90 c7 45 a4 0f 00 00 00 89 5d a0 88 5d 90 e8 e8 ?? ff ff 89 5d fc 8b 4d 90 bf 10 00 00 00 39 7d a4 73 02 8b ce 8b 55 a0 52 68 [3] 00 be [3] 00 e8 [2] 00 00 e8 }
        $s2 = { c1 ea 08 8b 35 04 ?? 41 00 88 55 f9 8b d0 c1 ea 10 88 45 f4 88 55 f6 8b d1 c1 e8 18 88 4d f8 c1 e9 18 88 45 f7 8d 45 dc 50 88 4d fb 8d 4d e0 51 6a 00 68 06 00 02 00 6a 00 6a 00 6a 00 68 [3] 00 c1 ea 10 68 01 00 00 80 c7 45 ?? 01 00 00 00 88 55 fa ff d6 8b ?? 00 ?? 41 00 }
        $s3 = { ff 15 [2] 41 00 8d 85 f8 fe ff ff 8d 50 01 [0-2] 8a 08 40 84 c9 75 f9 2b c2 50 8d 95 f8 fe ff ff 52 68 [2] 42 00 e8 [2] 00 00 83 c4 0c 8d 85 f8 fe ff ff 50 ff 15 [2] 41 00 85 }
        $s4 = { 83 c4 0c 8d ?? e0 ?? ff ff ?? 8d ?? e0 ?? ff ff ?? ff 15 [2] 41 00 68 60 ?? 42 00 8d ?? e0 ?? ff ff ?? ff 15 [2] 41 00 6a 44 8d ?? f8 ?? ff ff 56 ?? e8 [2] 00 00 83 c4 0c 33 ?? 8d ?? 44 ?? ff ff ?? 89 ?? 28 ?? ff ff 8d ?? f8 ?? ff ff ?? 56 56 56 6a 01 56 56 8d ?? e0 ?? ff ff ?? 56 c7 85 f8 ?? ff ff 44 00 00 00 89 b5 fc ?? ff ff 89 b5 00 ?? ff ff 89 b5 04 ?? ff ff c7 85 24 ?? ff ff 01 01 00 00 89 b5 }
   condition:
       uint16(0) == 0x5A4D and filesize > 70KB and all of ($s*)
}
