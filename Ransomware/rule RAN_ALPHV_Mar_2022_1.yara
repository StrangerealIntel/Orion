rule RAN_ALPHV_Mar_2022_1 : alphav blackcat ransomware
{
    meta:
        description = "Detect new variant of AlphV ransomware"
        author = "Arkbird_SOLG"
        date = "2022-03-19"
        // Updated with "ALPHV MORPH" variant 2
        reference = "https://twitter.com/rivitna2/status/1636891502562385920"
        hash1 = "62ae5ad22213d2adaf0e7cf1ce23ff47b996f60065244b63f361a22daed2bdda"
        hash2 = "1d6d47bf20d21b860d232a358481c477c36491134ea976372c69a0483e05a556"
        hash3 = "38d5f4f37686dab8b082b591224e272883644caab6a814e7751981da00523c51"
        hash4 = "aba1639c22467782c13a6dbe25c7b79e75b40ab440b7b54454ae9bc54dd6ae51"
        tlp = "Clear"
        adversary = "BlackCat"
    strings:
        $s1 = { 55 89 e5 53 57 56 81 ec 2c 04 00 00 8d 85 c8 fb ff ff 6a 04 68 [3] 00 50 e8 71 f8 ff ff 83 c4 0c 83 bd c8 fb ff ff 00 74 33 8b 85 d0 fb ff ff f2 0f 10 85 c8 fb ff ff 89 45 ec f2 0f 11 45 e4 8b 45 e4 8b 5d 08 85 c0 74 30 8b 4d e8 8b 55 ec 89 03 89 53 08 89 4b 04 e9 3b 02 00 00 8d 45 e4 6a 0b 68 [3] 00 50 e8 22 f8 ff ff 83 c4 0c 8b 45 e4 8b 5d 08 85 c0 75 d0 e8 ?? 1a 08 00 c7 45 d4 }
        $s2 = { 53 57 56 83 ec 60 8b 5d 14 8b 75 18 e8 [3] 00 89 45 e8 8d 7d cc 56 53 57 e8 [2] 03 00 83 c4 0c 8d 5d b0 ff 75 20 ff 75 1c 53 e8 [2] 03 00 83 c4 0c 8d 75 94 ff 75 28 ff 75 24 56 e8 [2] 03 00 83 c4 0c 57 e8 [2] 03 00 83 c4 04 8b 38 89 55 ec 53 e8 [2] 03 00 83 c4 04 8b 18 89 55 f0 56 e8 [2] 03 00 83 c4 04 89 d6 8d 4d e8 51 ff 75 10 ff 75 0c ff 30 53 57 e8 [3] 00 85 c0 }
        $s3 = { 68 [3] 00 6a 00 6a 00 e8 ?? 79 06 00 85 c0 74 21 89 c6 31 c0 f0 0f b1 35 [3] 00 0f 84 0e ff ff ff 89 c7 56 e8 ?? 79 06 00 89 fe e9 ff fe ff ff }
        $s4 = { 5c 5c 2e 5c 70 69 70 65 5c 5f 5f 72 75 73 74 5f 61 6e 6f 6e 79 6d 6f 75 73 5f 70 69 70 65 31 5f 5f }
    condition:
       uint16(0) == 0x5A4D and filesize > 300KB and all of ($s*) 
} 
