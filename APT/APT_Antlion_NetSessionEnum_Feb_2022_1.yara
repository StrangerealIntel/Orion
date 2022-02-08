rule APT_Antlion_NetSessionEnum_Feb_2022_1
{
   meta:
        description = "Detect the NetSessionEnum tool"
        author = "Arkbird_SOLG"
        reference = "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/china-apt-antlion-taiwan-financial-attacks"
        date = "2022-02-05"
        hash1 = "48d41507f5fc40a310fcd9148b790c29aeb9458ff45f789d091a9af114f26f43"
        hash2 = "-"
        tlp = "White"
        adversary = "Antlion"
   strings:
        $s1 = { 8d 7c 24 0d c6 44 24 0c 00 f3 ab 8b 8c 24 98 13 00 00 8d 54 24 0c 66 ab aa 8d 84 24 9c 13 00 00 50 51 52 ff 15 3c 20 40 00 83 c4 0c 6a 00 68 80 00 00 00 6a 04 6a 00 6a 01 68 00 00 00 c0 68 10 30 40 00 ff 15 0c 20 40 00 8b f0 85 f6 74 3e 6a 02 6a 00 6a 00 56 ff 15 08 20 40 00 8d 44 24 08 6a 00 50 8d 7c 24 14 83 c9 ff 33 c0 f2 ae f7 d1 49 c7 44 24 10 00 00 00 00 51 8d 4c 24 18 51 56 ff 15 04 20 40 00 56 ff 15 }
        $s2 = { 8b 8c 24 3c 08 00 00 8b 11 52 68 7c 30 40 00 ff 15 40 20 40 00 83 c4 08 83 c8 ff 5f 5e 5d 5b }
        $s3 = { 8d 44 24 20 8d 4c 24 24 50 8d 54 24 18 51 8b 8c 24 a8 1b 00 00 52 8b 94 24 a8 1b 00 00 8d 44 24 1c 6a ff 50 6a 0a 51 52 55 e8 5d 05 00 00 8b f8 3b fb 89 7c 24 28 74 0c 81 ff ea 00 00 00 0f 85 31 01 00 00 8b 74 24 10 3b f3 0f 84 39 01 00 00 8b 44 24 14 89 5c 24 1c 3b }
        $s4 = { 8b 43 08 8b 4b 04 8b 13 50 51 52 8d 44 24 70 68 f4 30 40 00 50 ff 15 8c 20 40 00 83 c4 14 8d 4c 24 10 8d 54 24 20 51 52 55 55 6a 10 55 55 8d 84 24 80 00 00 00 55 50 55 ff 15 24 20 40 00 f7 d8 }
        $s5 = "Usage: %s ServerFile [UserFile] [/e]\n" wide
    condition:
        uint16(0) == 0x5A4D and filesize > 3KB and filesize < 30KB and 4 of ($s*) 
}
