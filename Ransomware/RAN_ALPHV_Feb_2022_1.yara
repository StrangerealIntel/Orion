rule RAN_ALPHV_Feb_2022_1 : alphav blackcat ransomware
{
    meta:
        description = "Detect AlphV ransomware (November 2021)"
        author = "Arkbird_SOLG"
        date = "2022-02-27"
        // Last updated 2022-03-18
        reference = "Internal Research"
        hash1 = "7bb383b31d1b415bc067e612203cc6bda53e914f7ca5291299e92f59d47cabf8"
        hash2 = "bacedbb23254934b736a9daf6de52620c9250a49686d519ceaf0a8d25da0a97f"
        // Updated with "ALPHV MORPH" variant
	    hash3 = "3a96c3075b8494fe6a76c6325946ab3f200e75ce26ad886446ea1394b5ac6ba1"
	    hash4 = "6dd995d896a9a593b2c48d09da60bd83866d8577273f36d38788d83ad8173e68"
        tlp = "white"
        adversary = "BlackCat"
    strings:
        $s1 = { 56 53 e8 [3] 00 85 c0 74 ?? 8d 4c 24 08 8d 94 24 e0 00 00 00 ff b4 24 c0 00 00 00 e8 [3] 00 83 c4 04 83 7c 24 08 00 [2-6] 8b 44 24 0c 85 c0 74 18 f7 44 24 10 ff ff ff 7f 74 0e 50 6a 00 ff 35 }
        $s2 = { 53 57 56 e8 [3] 00 83 c4 0c 8d 04 1e 8d 4d dc 89 f2 6a 00 50 e8 [3] 00 83 c4 08 8b 45 e4 f2 0f 10 45 dc 8d 4d d0 89 45 d8 f2 0f 11 45 d0 e8 [4] 89 c7 85 db 89 55 f0 74 0e 56 6a 00 ff 35 [3] 00 e8 [3] 00 6a 2c 57 8b 45 e8 ff 30 e8 [3] 00 85 c0 74 28 8b 55 08 f7 45 f0 ff ff ff 7f 8b 75 ec 8b 4a 08 f2 0f 10 02 89 4e 08 f2 0f 11 06 89 46 0c 66 c7 07 00 00 74 40 57 eb 30 8b 45 ec f7 45 f0 ff ff ff 7f c7 00 00 00 00 00 66 c7 07 00 00 74 0e 57 6a 00 }
        $s3 = { c6 05 [3] 00 01 8b 35 [3] 00 85 f6 74 47 8b 3d [3] 00 85 ff 0f 85 81 00 00 00 eb 60 68 [3] 00 6a 00 6a 00 e8 [3] 00 85 c0 0f 84 99 01 00 00 89 c1 31 c0 f0 0f b1 0d [3] 00 0f 84 f0 fe ff ff 89 c6 51 e8 [3] 00 89 f1 e9 e1 fe ff ff 68 [3] 00 ff 35 [3] 00 e8 [3] 00 85 c0 0f 84 32 03 00 00 89 c6 a3 [3] 00 }
        $s4 = { 8b 3d [3] 00 c7 00 01 00 00 00 c7 40 04 01 00 00 00 c6 40 08 00 89 44 24 3c 89 7c 24 40 c7 44 24 44 00 00 00 00 89 bc 24 ac 00 00 00 c7 84 24 b0 00 00 00 00 00 00 00 c7 44 24 48 00 00 00 00 c7 84 24 b4 00 00 00 00 00 00 00 68 3f 00 0f 00 6a 00 6a 00 e8 [3] 00 85 c0 0f 84 ?? 0b 00 00 89 7c 24 50 89 c6 8d 9c 24 b8 00 00 00 8d 7c 24 4c c7 44 24 54 00 00 00 00 c7 44 24 4c 00 00 00 00 c7 84 24 b8 00 00 00 00 00 00 00 c7 44 24 58 00 00 00 00 6a 00 6a 00 53 57 6a 00 6a 00 6a 01 6a 30 6a 00 50 e8 [3] 00 8b 4c 24 4c 8b 15 [3] 00 31 c0 89 b4 24 bc 00 00 00 89 0c 24 85 c9 b9 00 00 00 00 89 54 24 30 c7 44 24 34 00 00 00 00 c7 44 24 38 00 00 00 }
    condition:
       uint16(0) == 0x5A4D and filesize > 300KB and all of ($s*) 
} 
