rule RAN_ALPHV_Apr_2022_1 : alphav blackcat ransomware
{
    meta:
        description = "Detect AlphV ransomware (Rust version)"
        author = "Arkbird_SOLG"
        date = "2022-04-03"
        reference = "Internal Research"
        hash1 = "6229f6de17bf83d824249a779b3f2a030cb476133ab8879c0853bab4fdf9c079"
        hash2 = "847fb7609f53ed334d5affbb07256c21cb5e6f68b1cc14004f5502d714d2a456"
        tlp = "Clear"
        adversary = "BlackCat"
    strings:
        $s1 = { 68 [3] 00 6a 00 6a 00 e8 [3] 00 85 c0 0f 84 [2] 00 00 89 ?? 31 c0 f0 0f b1 [5] 0f 84 ?? fe ff ff 89 c6 ?? e8 [3] 00 89 ?? e9 ?? fe ff ff 68 [3] 00 ff 35 [4] e8 [3] 00 85 c0 0f 84 [2] 00 00 }
        $s2 = { 5c 00 5c 00 3f 00 5c 00 [0-2] 5c 00 5c 00 3f 00 5c 00 55 00 4e 00 43 00 5c 00 5c 5c 2e 5c 70 69 70 65 5c 5f 5f 72 75 73 74 5f 61 6e 6f 6e 79 6d 6f 75 73 5f 70 69 70 65 31 5f 5f 2e }
        $s3 = { 00 00 8d ?? 24 [2] 00 00 [1-4] 00 02 00 00 89 ?? 24 ?? 6a 00 e8 [3] 00 [0-1] 57 [0-1] e8 [3] 00 89 ?? 85 c0 75 0d e8 [3] 00 85 c0 0f 85 ?? 00 00 00 39 ?? 0f 85 ?? ff ff ff e8 [3] 00 83 f8 7a 0f 85 ?? ff ff ff 01 ?? 81 ?? 01 02 00 00 72 }
        $s4 = { 65 74 53 65 72 76 65 72 45 6e 75 6d 00 ?? 00 4e 65 74 53 68 61 72 65 45 6e 75 6d }
    condition:
       uint16(0) == 0x5A4D and filesize > 90KB and all of ($s*) 
} 
