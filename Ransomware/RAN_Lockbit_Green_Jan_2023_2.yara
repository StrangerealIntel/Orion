rule RAN_Lockbit_Green_Jan_2023_2 : ransomware green lockbit x64
{
    meta:
        description = "Detect the green variant used by lockbit group (x64)"
        author = "Arkbird_SOLG"
        date = "2023-01-30"
        reference = "https://github.com/prodaft/malware-ioc/blob/master/LockBit/green.md"
        hash1 = "b3ea0f4f442da3106c0d4f97cf20e244b84d719232ca90b3b7fc6e59e37e1ca1"
        hash2 = "fb49b940570cfd241dea27ae768ac420e863d9f26c5d64f0d10aea4dd0bf0ce3"
        tlp = "Clear"
        adversary = "RAAS"
    strings:
        $s1 = { 48 8d 4d fd 0f b6 45 fe e8 [2] 01 00 4c 8b 85 d0 00 00 00 48 8d 8d 10 01 00 00 48 8b d0 ff 15 [2] 02 00 ba 0f 00 00 00 c7 85 50 09 00 00 [3] 00 33 c9 41 b8 09 a2 26 51 44 8d 4a 56 e8 [2] ff ff 48 8d 4c 24 58 ff d0 b8 56 55 55 55 c7 85 50 09 00 00 [3] 00 8b 8d 50 09 00 00 f7 e9 8b c2 c1 e8 1f 03 d0 8d 04 52 3b c8 74 ?? 8b 8d 50 09 00 00 8b 44 24 58 83 c0 02 03 c8 89 8d 50 09 00 00 8b 85 50 09 00 00 25 }
        $s2 = { 48 2b d6 48 8d 4c 24 30 48 ff c2 41 b8 40 01 00 00 f6 d8 4d 1b ff 4c 23 fa 33 d2 e8 [2] ff ff 45 33 c9 89 7c 24 28 4c 8d 44 24 30 48 89 7c 24 20 33 d2 48 8b ce ff 15 [2] 00 00 48 8b d8 48 83 f8 ff 75 4a 4d 8b ce 45 33 c0 33 }
        $s3 = { 48 83 64 24 38 00 48 8d 45 e8 48 83 64 24 30 00 4c 8d 45 c0 8b 4d cc 41 b9 01 00 00 00 c7 44 24 28 05 00 00 00 33 d2 48 89 44 24 20 48 ff c7 ff 15 [2] 00 00 44 8b f0 85 c0 0f 84 94 00 00 00 48 8b 4d d0 4c 8d 4d c8 48 83 64 24 20 00 48 8d 55 e8 44 8b c0 ff 15 [2] 00 00 33 d2 85 c0 74 6b 8b 4b 08 2b 4d d8 03 cf 89 4b 04 44 39 75 c8 72 62 41 80 fd 0a 75 34 48 8b 4d d0 8d 42 0d 48 89 54 24 20 44 8d 42 01 48 8d 55 c4 66 89 45 c4 4c 8d 4d c8 ff 15 [2] 00 00 33 d2 85 c0 74 2c 83 7d c8 01 }
    condition:
       uint16(0) == 0x5A4D and filesize > 80KB and all of ($s*)
}
