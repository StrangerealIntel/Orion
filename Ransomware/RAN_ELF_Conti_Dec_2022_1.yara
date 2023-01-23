rule RAN_ELF_Conti_Dec_2022_1 : ransomware conti elf
{
    meta:
        description = "Detect ELF version of Conti ransomware"
        author = "Arkbird_SOLG"
        date = "2022-12-10"
        reference = "Internal Research"
        hash1 = "13fa3e25f69c4e0c8f79208b8ab227d8a43df72b458b4825190d05697656d907"
        hash2 = "35ea625eb99697efdeb016192b25c5323ec10b0b33642cd9b2641e058e5e8dc6"
        hash3 = "67b96ba4d6d603ae7dee2882f605dd4e1fe38be1e46d9c8a8097af410fe34aa4"
        tlp = "Clear"
        adversary = "RAAS"
    strings:
        $s1 = { 48 83 ec 30 48 89 7d d8 c7 45 fc 00 00 00 00 c7 45 f8 00 00 00 00 48 8b 45 d8 8b 40 0c 89 45 f4 48 8b 45 d8 8b 40 0c 89 45 fc 8b 45 fc 48 98 48 89 c7 e8 [2] ff ff 48 89 45 e8 48 8b 45 d8 8b 40 08 ba 00 00 00 00 be 00 00 00 00 89 c7 e8 [2] ff ff 8b 45 fc 48 63 d0 48 8b 45 d8 8b 40 08 48 8b 4d e8 48 89 ce 89 c7 e8 [2] ff ff 48 85 c0 0f 94 c0 84 c0 74 19 48 8d 05 [2] 00 00 48 89 c7 e8 [2] ff ff b8 00 00 00 00 }
        $s2 = { 48 83 ec 10 48 89 7d f8 48 8b 45 f8 48 83 c0 58 be 20 00 00 00 48 89 c7 e8 [2] ff ff 83 f8 ff 74 1a 48 8b 45 f8 48 83 c0 50 be 08 00 00 00 48 89 c7 e8 [2] ff ff 83 f8 ff 75 07 b8 01 00 00 00 eb 05 b8 00 00 00 00 84 c0 74 1b 48 8d 05 [2] 00 00 48 89 c7 b8 00 00 00 00 e8 [2] ff ff }
        $s3 = { 48 8b 45 e0 0f b6 00 0f b6 d0 48 8b 45 e0 48 83 c0 01 0f b6 00 0f b6 c0 c1 e0 08 09 c2 48 8b 45 e0 48 83 c0 02 0f b6 00 0f b6 c0 c1 e0 10 09 c2 48 8b 45 e0 48 83 c0 03 0f b6 00 0f b6 c0 c1 e0 18 09 c2 48 8b 45 e8 89 50 20 48 8b 45 e0 48 83 c0 04 0f b6 00 0f b6 d0 48 8b 45 e0 48 83 c0 05 0f }
        $s4 = { 55 48 89 e5 48 81 ec 20 03 00 00 48 8d 85 e0 fc ff ff 48 8d 15 [2] 00 00 b9 ?? 00 00 00 48 89 c7 48 89 d6 f3 48 a5 48 }
    condition:
       uint32(0) == 0x464C457F and filesize > 10KB and all of ($s*) 
}
