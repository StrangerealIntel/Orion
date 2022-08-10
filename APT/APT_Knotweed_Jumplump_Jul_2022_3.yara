rule APT_Knotweed_Jumplump_Jul_2022_3 : jumplump knotweed loader
{
   meta:
        description = "Detect the Jumplump loader used by the knotweed group"
        author = "Arkbird_SOLG"
        reference = "https://www.microsoft.com/security/blog/2022/07/27/untangling-knotweed-european-private-sector-offensive-actor-using-0-day-exploits/"
        date = "2022-07-29"
        hash1 = "7f84bf6a016ca15e654fb5ebc36fd7407cb32c69a0335a32bfc36cb91e36184d"
        hash2 = "fd6515a71530b8329e2c0104d0866c5c6f87546d4b44cc17bbb03e64663b11fc"
        tlp = "Clear"
        adversary = "Knotweed"
   strings:
        $s1 = { 48 83 ec 50 48 8b 05 [2] 04 00 48 33 c4 48 89 44 24 48 33 f6 66 3b 35 [2] 04 00 0f 85 ?? 00 00 00 49 8d 43 e0 }
        $s2 = { 48 ?? ec [1-4] 48 8b 05 [3] 00 48 33 c4 48 89 ?? 24 [3-7] 48 8d 44 24 }
        $s3 = "\\system32\\propsys.dll" wide
        $s4 = { 4c 89 4c 24 20 4d 8b c8 4c 8b c2 48 8d 15 [3] 00 e8 [4] eb ?? 4c 8b c2 48 8d 15 [3] 00 (e8 d8 fe ff ff eb 21 | 48 83 c4 38 e9 98 03 00 00 ) 4d 85 c0 74 09 48 8d 15 [3] 00 eb }
        $s5 = "%s.%1d.ver0x%08x%08x.db" wide
   condition:
       uint16(0) == 0x5A4D and filesize > 90KB and all of ($s*)
}
