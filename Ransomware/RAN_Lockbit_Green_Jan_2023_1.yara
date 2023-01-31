rule RAN_Lockbit_Green_Jan_2023_1 : ransomware green lockbit x86
{
    meta:
        description = "Detect the green variant used by lockbit group (x86)"
        author = "Arkbird_SOLG"
        date = "2023-01-30"
        reference = "https://github.com/prodaft/malware-ioc/blob/master/LockBit/green.md"
        hash1 = "45c317200e27e5c5692c59d06768ca2e7eeb446d6d495084f414d0f261f75315"
        hash2 = "27b8ee04d9d59da8e07203c0ab1fc671215fb14edb35cb2e3122c1c0df83bff8"
        tlp = "Clear"
        adversary = "RAAS"
    strings:
        $s1 = { 8b 3d [4] 66 90 8b 01 8d 95 f4 f7 ff ff 52 8d 95 a8 f7 ff ff 52 6a 01 6a ff 51 ff 50 10 8b f0 c7 85 8c f7 ff ff [3] 00 8b 85 8c f7 ff ff 99 f7 fb 8b 85 8c f7 ff ff 85 d2 74 51 83 c0 02 03 c6 89 85 8c f7 ff ff 8b 85 8c f7 ff ff 25 03 00 00 80 79 07 48 83 c8 fc 83 c0 01 0f 85 6e 01 00 00 0f 1f 40 00 8b 85 8c f7 ff ff 40 89 85 8c f7 ff ff 8b 85 8c f7 ff ff 25 03 00 00 80 79 07 48 83 c8 fc 83 c0 }
        $s2 = { 8b 75 08 33 c0 57 8b 7d 0c 89 06 89 46 04 89 46 08 8b 45 10 03 c7 89 45 fc 3b f8 73 3f 0f b7 1f 53 e8 ?? 0b 00 00 59 66 3b c3 75 28 83 46 04 02 83 fb 0a 75 15 6a 0d 5b 53 e8 ?? 0a 00 00 59 66 3b }
        $s3 = { 0f b6 c0 2b cb 41 f7 d8 68 40 01 00 00 1b c0 23 c1 89 85 b4 fe ff ff 8d 85 bc fe ff ff 57 50 e8 ?? be ff ff 83 c4 0c 8d 85 bc fe ff ff 57 57 57 50 57 53 ff 15 [4] 8b f0 8b 85 b8 fe ff ff 83 fe ff 75 2d 50 57 57 53 e8 9f }
        $s4 = { 33 c9 8d 45 ec 51 51 6a 05 50 6a 01 8d 45 e8 47 50 51 ff 75 c8 ff 15 [4] 89 45 cc 85 c0 0f 84 91 00 00 00 6a 00 8d 4d e0 51 50 8d 45 ec 50 ff 75 d8 ff 15 [4] 85 c0 74 }
    condition:
       uint16(0) == 0x5A4D and filesize > 80KB and all of ($s*)
}
