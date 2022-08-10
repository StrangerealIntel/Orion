rule APT_Knotweed_Jumplump_Jul_2022_1 : jumplump knotweed loader
{
   meta:
        description = "Detect the Jumplump loader used by the knotweed group"
        author = "Arkbird_SOLG"
        reference = "https://www.microsoft.com/security/blog/2022/07/27/untangling-knotweed-european-private-sector-offensive-actor-using-0-day-exploits/"
        date = "2022-07-28"
        hash1 = "4611340fdade4e36f074f75294194b64dcf2ec0db00f3d958956b4b0d6586431"
        hash2 = "cbae79f66f724e0fe1705d6b5db3cc8a4e89f6bdf4c37004aa1d45eeab26e84b"
        hash3 = "5d169e083faa73f2920c8593fb95f599dad93d34a6aa2b0f794be978e44c8206"
        tlp = "Clear"
        adversary = "Knotweed"
   strings:
        $s1 = { 48 8d ( 45 0b | 44 24 60 ) c7 ( 45 0f | 44 24 60 ) 04 00 00 00 48 89 44 24 [2] 8d (15 9f 7b 06 | 05 20 4e 01 ) 00 48 8d }
        $s2 = { 8b [2] 89 ?? 24 ?? 4c [2] 24 ?? 4d 8b ?? 4c 8d 05 ( d0 38 05 | 09 74 04 ) 00 ba 04 01 00 00 48 8d 8c 24 [2] 00 00 e8 ?? 01 00 00 85 c0 78 ?? 48 89 ?? 24 40 48 ?? 44 24 40 48 }
        $s3 = { 48 83 ec 48 48 8b 44 24 48 4c 8d 05 [2] 02 00 c7 44 24 38 ff ff 00 80 45 33 c9 c7 44 24 30 03 00 00 00 ba [2] 00 00 48 89 44 24 28 48 83 64 24 20 00 e8 [3] ff 48 83 }
        $s4 = { 4c 00 6f 00 63 00 61 00 6c 00 5c 00 53 00 4d 00 30 00 3a 00 25 00 64 00 3a 00 25 00 64 00 3a 00 25 00 68 00 73 }
        $s5 = { 4c 8d 05 [2] 02 00 48 8b ?? 48 8b c8 e8 [2] 00 00 4c 8b ?? 10 4d 85 c9 74 12 4c 8d 05 [2] 02 00 48 8b ?? 48 8b c8 e8 [2] 00 00 4c 8b ?? 40 4d 85 c9 74 12 4c 8d 05 [2] 02 00 48 8b ?? 48 8b c8 e8 }
   condition:
       uint16(0) == 0x5A4D and filesize > 90KB and all of ($s*)
}
