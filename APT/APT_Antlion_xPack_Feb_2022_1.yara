rule APT_Antlion_xPack_Feb_2022_1
{
   meta:
        description = "Detect the XPack loader"
        author = "Arkbird_SOLG"
        reference = "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/china-apt-antlion-taiwan-financial-attacks"
        date = "2022-02-04"
        hash1 = "390460900c318a9a5c9026208f9486af58b149d2ba98069007218973a6b0df66"
        hash2 = "12425edb2c50eac79f06bf228cb2dd77bb1e847c4c4a2049c91e0c5b345df5f2"
        tlp = "Clear"
        adversary = "Antlion"
   strings:
        $s1 = { 1f 40 8d ?? 00 00 01 25 d0 ?? 00 00 04 28 ?? 00 00 0a 0a 03 1f 3d }
        $s2 = { 00 00 0a [2] 11 [1-6] 11 ?? 6f ?? 00 00 0a 6f ?? 00 00 0a [1-3] 11 ?? 16 8c ?? 00 00 01 17 8d ?? 00 00 01 25 16 16 8d ?? 00 00 01 a2 6f ?? 00 00 0a 26 [2-8] 6f ?? 00 00 0a 28 ?? 00 00 0a [0-2] de 00 }
        $s3 = { 00 00 0a 0a [0-1] 06 6f ?? 00 00 0a [1-2] 20 00 00 02 00 8d ?? 00 00 01 ?? 15 [0-2] 0d 16 13 04 [0-3] 1f 10 8d ?? 00 00 01 13 ?? 06 11 ?? 16 1f 10 6f ?? 00 00 0a 26 1f 10 8d ?? 00 00 01 13 ?? 06 11 ?? 16 1f 10 6f }
        $s4 = { 02 7b 02 00 00 04 8d ?? 00 00 01 0a 02 7b 03 00 00 04 8d ?? 00 00 01 0b 16 13 ?? 2b }
    condition:
        uint16(0) == 0x5A4D and filesize > 5KB and all of ($s*) 
}
