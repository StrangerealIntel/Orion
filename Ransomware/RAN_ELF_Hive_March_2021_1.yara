rule RAN_ELF_Hive_March_2021_1 : elf hive v5 x64
{
   meta:
        description = "Detect ELF version of Hive ransomware (x64 version)"
        author = "Arkbird_SOLG"
        reference = "Internal Research"
        date = "2021-03-26"
        hash1 = "058aabdef6b04620902c4354ce40c2e2d8ff2c0151649535c66d870f45318516"
        hash2 = "2e52494e776be6433c89d5853f02b536f7da56e94bbe86ae4cc782f85bed2c4b"
        tlp = "white"
        adversary = "Hive"
        level = "Experimental"
   strings:
        $s1 = { ff 54 1d 00 84 c0 75 43 48 83 c3 10 49 83 c7 ff 75 c6 48 8b 54 24 40 eb 02 31 d2 48 89 d1 48 c1 e1 04 49 03 0c 24 31 c0 49 3b 54 24 08 48 0f 42 c1 73 1c 48 8b }
        $s2 = { 48 8d 1d d5 b1 23 00 49 89 de 49 c1 ee 08 48 c1 e3 38 48 83 cb 28 41 b7 04 80 f9 03 75 54 48 8b 6c 24 18 48 8b 7d 00 48 8b 45 08 ff 10 48 8b 45 08 48 83 78 08 00 74 0a 48 8b 7d 00 ff 15 5a c8 23 00 48 8b 7c 24 18 ff 15 4f c8 23 00 eb }
        $s3 = { 48 8d 05 67 b2 23 00 48 89 44 24 10 48 c7 44 24 18 01 00 00 00 48 c7 44 24 20 00 00 00 00 48 8d 05 49 0b 03 00 48 89 44 24 30 48 c7 44 24 38 00 00 00 00 48 8d 74 24 10 4c 89 ff 41 ff d5 3c 03 0f 85 a1 00 00 00 48 89 d3 eb 76 4c 8d 25 e4 c8 23 00 4c 89 e7 ff 15 43 c7 23 00 88 5c 24 0f 48 8d 44 24 0f 48 89 44 24 40 48 8d 05 1e 0c 00 00 48 89 44 24 48 48 8d 05 4a ab 23 00 48 89 44 24 10 48 c7 44 24 18 01 00 00 00 48 c7 44 24 20 00 00 00 00 4c 89 74 24 30 48 c7 44 24 38 01 00 00 00 48 8d 74 24 10 4c 89 ff 41 ff d5 49 89 c6 48 89 d3 4c 89 e7 ff 15 7b c5 23 00 41 80 fe 03 75 26 48 8b 3b 48 8b 43 08 ff 10 48 8b 43 08 48 83 78 08 00 74 09 48 8b 3b ff 15 58 }
        $s4 = { 49 8b 1f 49 8b 6f 08 48 89 df ff 55 00 48 83 7d 08 00 74 09 48 89 df ff 15 5e 40 21 00 4c 89 ff ff 15 55 40 21 00 48 8b 44 24 18 f0 48 ff 08 75 0a 48 8d 7c 24 18 e8 cc 00 00 00 49 c1 e6 20 48 8b 44 24 10 f0 48 ff 08 75 0a 48 8d 7c 24 10 e8 b9 f9 ff ff 48 8d 54 24 50 4c 89 32 48 c7 42 08 00 00 00 00 48 8d 3d 3e 89 00 00 48 8d 0d 19 3b 21 00 4c 8d 05 12 3d 21 00 be 2b 00 00 00 eb 31 48 29 e8 48 8d 54 24 50 48 89 02 48 89 6a 08 4c 89 62 10 4c 89 62 18 48 8d 3d 64 88 00 00 48 8d 0d 86 3a 21 00 4c 8d 05 1f 3a 21 00 be 2f 00 00 }
   condition:
        uint32(0) == 0x464C457F and filesize > 60KB and all of ($s*) 
}
