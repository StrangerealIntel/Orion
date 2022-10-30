rule RAN_ESXI_Hive_Oct_2022_1 : esxii hive v5 x64
{
   meta:
        description = "Detect Rust version of Hive v5.4 ransomware (x64 version) used against ESXI servers"
        author = "Arkbird_SOLG"
        reference = "Internal Research"
        date = "2022-10-30"
        hash1 = "a0a87db436f4dd580f730d7cbe7df9aa7d94a243aab1e600f01cde573c8d10b8"
        hash2 = "f78fdb894624b1388c1c3ec1600273d12d721da5171151d6606a625acf36ac30"
        tlp = "Clear"
        adversary = "RAAS"
   strings:
        $x1 = { 00 00 00 48 8d ?? 24 98 02 00 00 48 8d 35 [2] 04 00 e8 [2] 03 00 48 8b 84 24 a8 02 00 00 48 8d 4c 24 54 48 89 41 10 0f 10 84 24 98 02 00 00 0f 11 01 48 8b b4 24 60 02 00 00 48 3b b4 24 58 02 00 00 75 15 48 8d bc 24 50 02 00 00 e8 [2] ff ff 48 8b b4 24 60 02 00 00 48 8b 84 24 50 02 00 00 48 89 f1 48 c1 e1 05 44 89 24 08 0f 10 44 24 50 0f 10 4c 24 5c 0f 11 44 08 04 }
        $x2 = { bf fd 02 00 00 41 b8 06 00 00 00 be 01 00 00 00 ba 01 00 00 00 [14-24] ff ff 84 c0 0f 85 [2] 00 00 48 89 ?? 48 8d 35 [3] 00 48 8d 15 }
        $s1 = { 2f 70 72 6f 63 2f 73 65 6c 66 2f 65 78 65 6e 6f 20 2f 70 72 6f 63 2f 73 65 6c 66 2f 65 78 65 20 61 76 61 69 6c 61 62 6c 65 2e 20 49 73 20 2f 70 72 6f 63 20 6d 6f 75 6e 74 65 64 3f 5c 78 }
        $s2 = { 2f 75 73 72 2f 6c 69 62 2f 64 65 62 75 67 2f 75 73 72 2f 6c 69 62 2f 64 65 62 75 67 2f 2e 62 75 69 6c 64 2d 69 64 2f 2e 64 65 62 75 67 5f 5f 70 74 68 72 65 61 64 5f 67 65 74 5f 6d 69 6e 73 74 61 63 6b } 
   condition:
        uint32(0) == 0x464C457F and filesize > 60KB and all of ($s*) and 1 of ($x*)
}
