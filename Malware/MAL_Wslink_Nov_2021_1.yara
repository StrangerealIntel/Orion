import "pe"
rule MAL_Wslink_Nov_2021_1 : loader wslink
{
   meta:
        description = "Detect WSLink loader"
        author = "Arkbird_SOLG"
        reference = "https://www.welivesecurity.com/2021/10/27/wslink-unique-undocumented-malicious-loader-runs-server/"
        date = "2021-11-01"
        hash1 = "9cb6c80e588a6f8c3e31b392f496b51ed5022d93029d5aae1954dbe80d12c80a"
        hash2 = "fcfae38ea48b6c0c7e6d7f176f03ee1a1bfcf457b41ef91c8ec8afb564234bf7"
        tlp = "Clear"
        adversary = "-"
   strings:
        $s1 = { 4c 89 4c 24 20 48 89 54 24 10 53 55 56 57 41 54 41 55 41 56 41 57 48 83 ec 28 33 f6 4c 8b f2 48 8b c1 8d 5e 01 4c 8d 69 0c 8b 49 08 44 8b d3 8b d3 4c 8b fe 41 d3 e2 8b 48 04 44 8a de d3 e2 48 8b 8c 24 a0 00 00 00 44 2b d3 2b d3 8b ee 44 8b e3 89 54 24 0c 8b 10 49 89 31 89 54 24 08 48 89 31 8b 48 04 03 ca ba 00 03 00 00 44 89 54 24 10 d3 e2 89 9c 24 80 00 00 00 89 5c 24 70 81 c2 36 07 00 00 89 5c 24 04 74 0d 8b ca 49 8b fd b8 00 04 00 00 }
        $s2 = { 41 0f b6 01 c1 e7 08 41 c1 e0 08 0b f8 4d 03 cb 41 0f b7 8c 55 c8 01 00 00 41 8b c0 c1 e8 0b 0f af c1 3b f8 73 1f 44 8b c0 b8 00 08 00 00 2b c1 c1 f8 05 66 03 c1 66 41 89 84 55 c8 01 00 00 8b 44 24 70 eb 24 44 2b c0 2b f8 0f b7 c1 66 c1 e8 05 66 2b c8 8b 44 24 04 66 41 89 8c 55 c8 01 00 00 8b 4c 24 70 89 4c 24 04 8b 8c 24 80 00 00 00 89 4c 24 70 44 89 a4 24 80 00 00 00 44 8b e0 83 fd 07 b8 0b 00 00 00 49 8d 95 68 0a 00 00 8d 68 fd 0f 4c c5 33 db 45 3b c2 89 04 24 73 19 4d 3b ce 0f 84 5f 03 00 00 41 0f b6 01 c1 e7 08 41 c1 e0 08 0b f8 4d 03 cb 0f b7 0a 41 8b c0 c1 e8 0b 0f }
        $s3 = { 43 0f b7 0c 53 41 8b c0 c1 e8 0b 0f af c1 3b f8 73 19 44 8b c0 b8 00 08 00 00 2b c1 c1 f8 05 66 03 c1 03 d2 66 43 89 04 53 eb 18 44 2b c0 2b f8 0f b7 c1 66 c1 e8 05 8d 54 12 01 66 2b c8 66 43 89 0c 53 83 eb 01 75 92 83 ea 40 83 fa 04 44 8b e2 0f 8c fb 00 00 00 41 83 e4 01 44 8b d2 41 d1 fa 41 83 cc 02 41 83 ea 01 83 }
        $s4 = { b8 00 08 00 00 44 8b c1 41 2b c2 c1 f8 05 66 41 03 c2 41 ba 00 00 00 01 41 3b ca 66 41 89 84 55 98 01 00 00 73 19 4d 3b ce 0f 84 3e 05 00 00 41 0f b6 01 c1 e7 08 41 c1 e0 08 0b f8 4d 03 cb 41 0f b7 8c 5d e0 01 00 00 41 8b c0 c1 e8 0b 0f af c1 3b f8 73 56 44 8b c0 b8 00 08 00 00 2b c1 c1 f8 05 66 03 c1 66 41 89 84 5d e0 01 00 00 33 c0 }
        $s5 = "WinorLoaderDll64.dll" ascii
   condition:
        uint16(0) == 0x5A4D and filesize > 60KB and all of ($s*) and 
        for any section in pe.sections : ( section.name == ".MPRESS1" or section.name == ".MPRESS2") // YARA 4.0+
        // legacy version
        // for any i in (0..pe.number_of_sections-1) : ( pe.sections[i].name == ".MPRESS1" or pe.sections[i].name == ".MPRESS2" )
}
