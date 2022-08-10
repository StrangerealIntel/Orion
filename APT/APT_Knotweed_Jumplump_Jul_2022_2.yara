rule APT_Knotweed_Jumplump_Jul_2022_2 : jumplump knotweed loader
{
   meta:
        description = "Detect the Jumplump loader used by the knotweed group"
        author = "Arkbird_SOLG"
        reference = "https://www.microsoft.com/security/blog/2022/07/27/untangling-knotweed-european-private-sector-offensive-actor-using-0-day-exploits/"
        date = "2022-07-29"
        hash1 = "02a59fe2c94151a08d75a692b550e66a8738eb47f0001234c600b562bf8c227d"
        hash2 = "894138dfeee756e366c65a197b4dbef8816406bc32697fac6621601debe17d53"
        hash3 = "afab2e77dc14831f1719e746042063a8ec107de0e9730249d5681d07f598e5ec"
        tlp = "Clear"
        adversary = "Knotweed"
   strings:
        $s1 = { 48 83 ec 20 33 db ?? 8b ?? 48 85 c9 74 3a 4c 8d 44 24 30 48 89 5c 24 30 ba ff ff ff 7f 48 8d 0d ?? ?? 02 00 e8 ?? ?? ?? ff 85 c0 78 1b 44 8b 44 24 30 48 8d 15 ?? ?? 02 00 ?? 8b ?? e8 ?? ?? ff ff 83 f8 02 75 02 b3 01 8a c3 }
        $s2 = { 48 83 ec 40 33 db 89 91 88 00 00 00 21 99 8c 00 00 00 48 8b f9 85 d2 75 06 48 21 59 38 eb 04 4c 89 49 78 48 21 99 80 00 00 00 48 8d 05 ?? ?? 00 00 48 8b 51 30 4c 8d 05 ?? ?? ?? 00 48 8b 49 28 45 33 c9 48 89 7c 24 30 48 21 5c 24 28 48 89 44 24 20 [0-1] ff 15 ?? ?? 04 00 [0-5] 85 c0 75 57 48 8b cf e8 ?? 00 00 00 8b d8 3d 04 40 00 80 75 17 8b 87 a8 00 00 00 85 c0 79 11 3d 0c 00 24 80 75 04 33 db eb 31 8b d8 85 db 79 2b 41 b9 03 00 00 00 48 8d 05 ?? ?? 01 00 48 89 44 24 28 48 8d 0d ?? ?? 02 00 ba ?? 02 00 00 89 5c 24 20 45 8d 41 1d e8 }
        $s3 = { 00 00 48 89 ?? 24 38 48 89 44 24 30 48 8d 05 [3] 00 48 89 44 24 28 48 [2] 24 20 [0-1] 41 b9 04 00 00 00 [0-6] 45 8b c7 33 d2 33 c9 e8 [3] ff 48 8b [2] 02 }
        $s4 = { 48 89 84 24 30 02 00 00 48 8b da 48 85 d2 [2-9] 48 83 22 00 4c 8d 05 [3] 00 48 8d 4c 24 20 e8 [4] 85 c0 78 0d 48 8b d3 48 8d 4c 24 20 e8 [4] 48 8b 8c 24 30 02 00 00 }
   condition:
       uint16(0) == 0x5A4D and filesize > 90KB and all of ($s*)
}
