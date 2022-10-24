rule RAN_Loader_Clop_Dec_2021_1
{
    meta:
        description = "Detect the loader used by TA505 group for inject Clop ransomware (unpacked file) "
        author = "Arkbird_SOLG"
        date = "2021-12-20"
        reference = "Internal Research"
        hash1 = "e805dd0124b9f062f6b5bc9de627eabc601b9d6e8ffe1d90ee552a1ece598a89"
        tlp = "Clear"
        adversary = "TA505"
        level = "Experimental"
    strings:
        $s1 = { 00 6a 00 68 9c 58 41 00 68 d0 58 41 00 6a 00 6a 00 ff 15 84 53 41 00 6a 00 6a 00 68 d8 58 41 00 68 0c 59 41 00 6a 00 6a 00 ff 15 84 53 41 00 6a 00 6a 00 68 14 59 41 00 68 48 59 41 00 6a 00 6a 00 ff 15 84 53 41 00 6a 00 6a 00 68 50 59 41 00 68 84 59 41 00 6a 00 6a 00 ff 15 84 53 41 00 6a 00 6a 00 68 8c 59 41 00 68 bc 59 41 00 6a 00 6a 00 ff 15 84 53 41 00 6a 00 6a 00 68 c4 59 41 00 68 f0 59 41 00 6a 00 6a 00 ff 15 84 53 41 00 e8 7e 0e 00 00 0f b6 d0 85 d2 74 0c c7 85 44 ec ff ff f8 59 41 00 eb 0a c7 85 44 ec ff ff 10 5a 41 00 8b 85 44 ec ff ff 89 85 38 ec ff ff 8b 8d 38 ec ff ff 51 8d 95 90 f4 ff ff 52 68 28 5a 41 00 68 04 01 00 00 68 04 01 00 00 8d 85 78 ee ff ff }
        $s2 = { 89 45 fc c6 85 e3 f9 ff ff 00 c6 85 e2 f9 ff ff 00 c7 85 dc f9 ff ff 00 00 00 00 68 04 01 00 00 8d 85 ec fb ff ff 50 ff 15 24 52 41 00 85 c0 0f 84 8b 00 00 00 83 bd dc f9 ff ff 00 74 16 8b 8d dc f9 ff ff 51 6a 00 ff 15 6c 52 41 00 50 ff 15 70 52 41 00 e8 37 fa ff ff 89 85 dc f9 ff ff 83 bd dc f9 ff ff 00 74 49 8b 95 dc f9 ff ff 52 8d 85 ec fb ff ff 50 68 1c d0 41 00 68 04 01 00 00 68 04 01 00 00 8d 8d f4 fd ff ff 51 e8 af f3 ff ff 83 c4 18 8b 55 0c 52 8b 45 08 50 8d 8d f4 fd ff ff 51 e8 48 f9 ff ff 83 c4 0c 88 85 e2 f9 ff ff 0f b6 95 }
        $s3 = "%s\\drivers\\%s.sys" wide
        $s4 = { 62 00 6c 00 61 00 63 00 6b 00 ( 6e 00 61 00 6d 00 65 00 73 | 73 00 69 00 67 00 6e 00 73 | 76 00 65 00 72 00 73 ) 00 2e 00 74 00 78 00 74 }
        $s5 = { 51 6a 00 6a 00 6a 25 6a 00 ff 15 80 53 41 00 e8 aa 0d 00 00 0f b6 d0 85 d2 74 0c c7 85 48 ec ff ff 34 5a 41 00 eb 0a c7 85 48 ec ff ff 50 5a 41 00 8b 85 48 ec ff ff 50 8d 8d 90 f4 ff ff 51 68 6c 5a 41 00 68 04 01 00 00 68 04 01 00 00 8d 95 88 f2 ff ff 52 e8 a4 08 00 00 83 c4 18 68 78 5a 41 00 8d 85 88 f2 ff ff }
    condition:
       uint16(0) == 0x5A4D and filesize > 30KB and 4 of ($s*) 
}