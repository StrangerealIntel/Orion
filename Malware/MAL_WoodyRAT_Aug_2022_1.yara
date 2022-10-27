rule MAL_WoodyRAT_Aug_2022_1 : woodyrat x64
{
    meta:
        description = "Detect WoodyRAT implant"
        author = "Arkbird_SOLG"
        date = "2022-08-04"
        reference = "https://blog.malwarebytes.com/threat-intelligence/2022/08/woody-rat-a-new-feature-rich-malware-spotted-in-the-wild/"
        hash1 = "408f3l14b0a76a0d41c99db0cb957d10ea8367700c757b0160ea925d6d7b5dd8e"
        hash2 = "6637871c18e9da070629a2dbbf39e5277e539e043b2b912cc3fed0209c48215d0b"
        hash3 = "43b1518071268f757027cf27dd94675fdd8e771cdcd77df6d2530cb8e218acc2ce"
        tlp = "Clear"
        adversary = "Woody" // internal name reference [WoodyRAT - WoodyPowerSession - WoodySharpExecutor]
    strings:
        $s1 = { 00 0f b7 08 66 89 0c 02 48 8d 40 02 66 85 c9 75 f0 c7 45 d8 18 00 00 00 ?? 89 ?? e0 c7 45 e8 01 00 00 00 45 33 c9 4c 8d 45 d8 48 8d 55 d0 48 8d 4d c8 ff 15 [2] 05 00 85 c0 0f 84 38 03 00 00 45 33 c9 4c 8d 45 d8 48 8d 55 c0 48 8d 4d b8 ff 15 [2] 05 00 85 c0 0f 84 07 03 00 00 c7 45 f0 68 00 00 00 c7 45 2c 01 01 00 00 48 8b 45 c0 48 89 45 50 48 89 45 48 48 8b 45 c8 48 89 45 40 66 [8] 00 00 [5] 48 }
        $s2 = { 48 8d ac 24 70 ff ff ff 48 81 ec 90 01 00 00 48 8b 05 [2] 06 00 48 33 c4 48 89 85 80 00 00 00 48 8b f9 48 89 4d b8 45 33 e4 44 89 64 24 40 4c 89 21 4c 89 61 08 4c 89 61 10 41 be 01 00 00 00 44 89 74 24 40 4c 89 65 60 4c 89 65 70 48 c7 45 78 07 00 00 00 66 44 89 65 60 ?? 8d }
        $s3 = { 0f 57 c0 0f 11 01 48 89 31 48 89 71 08 48 89 71 10 c7 44 24 40 01 00 00 00 33 c0 0f 11 45 68 48 89 45 78 48 89 74 24 70 }
        $s4 = { 8b d0 b9 40 00 00 00 ff 15 [2] 04 00 4c 8b f0 48 8d 45 ?? 48 89 44 24 20 44 8b 4d ?? 4d 8b c6 ba 02 00 00 00 48 c7 c1 fc ff ff ff ff 15 [2] 04 00 }
        $s5 = "S-1-5-32-544" wide // intergated administrators group
    condition:
       uint16(0) == 0x5A4D and filesize > 90KB and all of ($s*) 
} 
