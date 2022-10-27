rule RAN_LikeAHorse_Dec_2021_1
{
    meta:
        description = "Detect LikeAHorse ransomware (variant of GarrantDecrypt)"
        author = "Arkbird_SOLG"
        reference = "https://twitter.com/fbgwls245/status/1475677726988447746"
        hash1 = "6d2efda037fe23b1fe3a5bae44f5b9f7ddfdf621c5df6cb6999d801bbdf79b0f"
        hash2 = "5378249a2b439e92691fb87751adc9fc4e2dea1792309d695b7f1d9c6887b09d"
        hash3 = "6b0c2165483426a7ca50fbdc7b9403f75e03bc0e1117837054a36c0a98a400cf"
        hash4 = "7f4dba54da91c99423b5862088da784363c7edc76d63e26d72270cd1fdf6dbec"
        date = "2021-12-28"
        tlp = "Clear"
        adversary = "-"
    strings:
        $s1 = { 42 67 49 41 41 41 43 6b 41 41 42 53 55 30 45 78 41 43 }  
        $s2 = "C:\\Windows\\sysnative\\vssadmin.exe" wide
        $s3 = "netsh advfirewall set allprofiles state off" wide
        $s4 = "%appdata%\\_uninstalling_.png" wide
        $s5 = { 00 00 68 3c ?? 40 00 6a 00 6a 00 ff 77 08 ff 37 ff 35 44 ?? 40 00 ff 15 08 ?? 40 00 e8 [2] ff ff 8b f0 89 75 f4 85 f6 0f 84 d6 00 00 00 b9 00 04 00 00 e8 [2] ff ff 8b d8 85 db 75 08 6a 00 ff 15 [2] 40 00 ff 77 0c 8b 57 04 8b cb e8 ?? f3 ff ff 8b 47 0c c7 04 24 00 04 00 00 89 45 fc 8d 45 fc 50 53 6a 00 6a 01 6a 00 56 ff 15 0c ?? 40 00 85 c0 74 76 8b 55 fc 51 8b cb e8 ?? eb ff ff 59 6a 00 6a 06 6a 02 6a 00 6a 01 a3 40 ?? 40 00 8d 85 e8 fd ff ff 68 00 00 00 40 50 ff 15 [2] 40 00 89 45 f8 83 f8 ff 74 41 6a 00 8d 45 f0 50 ff 35 40 ?? 40 00 ff 15 [2] 40 00 8b 35 4c ?? 40 00 40 50 ff 35 40 ?? 40 00 ff 75 f8 ff d6 6a 00 8d 45 f0 50 ff 77 08 ff 37 ff 75 f8 ff d6 ff 75 f8 ff 15 [2] 40 00 8b 75 f4 ba 00 04 00 00 8b cb e8 ?? f2 ff ff e8 ?? f2 ff ff 56 ff 15 28 ?? 40 00 8b 57 0c 8b 4f 04 e8 ?? f2 ff ff 8b cf e8 [2] ff ff e8 ?? fb ff ff 6a 00 ff 35 44 ?? 40 00 ff 15 18 ?? 40 00 e8 [2] ff ff e9 0b }
    condition:
        uint16(0) == 0x5A4D and filesize > 6KB and all of ($s*) 
}
