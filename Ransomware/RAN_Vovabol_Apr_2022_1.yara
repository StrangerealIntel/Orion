rule RAN_Vovabol_Apr_2022_1 : vovabol ransomware
{
    meta:
        description = "Detect vovabol ransomware"
        author = "Arkbird_SOLG"
        date = "2022-04-06"
        reference = "https://id-ransomware.blogspot.com/2022/03/vovabol-ransomware.html"
        hash1 = "32c5e5f424698791373a921e782e4e42a6838a68aac00d4584c16df428990e19"
        hash2 = "3e4828a46b84a5cc0e095cc017e79a512f5f7deeefe39ddf073e527be66fcf56"
        hash3 = "7d6d38f2cbe320aff29eb02998476e731d02ca27ca0e2f79063b207fc10229e8"
        hash4 = "e4defd8a187a513212cb19c9f2a800505395e66d9cd9eb3a96c291060224e7dd"
        tlp = "Clear"
        adversary = "-"
    strings:
        $s1 = { 68 [2] 43 00 ff 15 ?? 10 40 00 89 [5-11] 08 00 00 00 6a 00 8d [3-6] ff 15 ?? 10 40 00 dd 9d [1-2] ff ff [0-1] 8d 4d ?? ff 15 [2] 40 00 8d }
        $s2 = { 00 00 00 ?? 68 [2] 43 00 ff 15 ?? 10 40 00 8b d0 8d 4d ?? ff 15 ?? 11 40 00 8b d0 8b 4d 08 83 c1 ?? ff 15 ?? 11 40 00 8d 4d ?? ff 15 ?? 11 40 00 c7 45 fc ?? 00 00 00 c7 [2-5] 04 00 02 80 c7 [2-5] 0a 00 00 00 8d [3-6] ff 15 ?? 11 40 00 8b }
        $s3 = { ff 15 ?? 11 40 00 66 89 45 dc 8d [2-5] ff 15 18 10 40 00 c7 45 fc ?? 00 00 00 [5-14] 8d 4d ?? ff 15 ?? 11 40 00 }
        $s4 = { 47 65 74 4c 6f 67 69 63 61 6c 44 72 69 76 65 73 00 00 00 00 [2] 43 00 [2] 43 00 00 00 04 00 70 ?? 44 00 00 00 00 00 00 00 00 00 a1 78 ?? 44 00 0b c0 74 02 ff e0 68 [2] 43 00 b8 [2] 40 00 ff d0 ff e0 00 00 00 0f 00 00 00 46 69 6e 64 46 69 72 73 74 46 69 6c 65 41 }
    condition:
       uint16(0) == 0x5A4D and filesize > 90KB and all of ($s*) 
} 
