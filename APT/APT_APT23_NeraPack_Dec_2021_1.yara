rule APT_APT23_NeraPack_Dec_2021_1
{
   meta:
        description = "Detect the NeraPack loader"
        author = "Arkbird_SOLG"
        reference = "https://cyberworkx.in/2021/12/22/cyber-espionage-hackers-from-tropic-trooper-are-targeting-the-transportation-sector/"
        date = "2021-12-26"
        hash1 = "3ad24a438b9a67e4eff7ca7d34b06d5efc24b824e3e346488d534532faa619da"
        hash2 = "a64e0c21494811ededf5d8af41b00937c1d5787d63dfcc399a7f32c19a553c99"
        hash3 = "321febf2bc5603b58628e3a82fb063027bf175252a3b30869eccb90a78e59582"
        tlp = "White"
        adversary = "APT23"
   strings:
        $s1 = { 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a [6] 00 }
        $s2 = { 00 00 0a [2] 11 [1-6] 11 ?? 6f ?? 00 00 0a 6f ?? 00 00 0a [1-3] 11 ?? 16 8c ?? 00 00 01 17 8d ?? 00 00 01 25 16 16 8d ?? 00 00 01 a2 6f ?? 00 00 0a 26 [2-8] 6f ?? 00 00 0a 28 ?? 00 00 0a [0-2] de 00 }
        $s3 = { 00 00 0a 0a [0-1] 06 6f ?? 00 00 0a [1-2] 20 00 00 02 00 8d ?? 00 00 01 ?? 15 [0-2] 0d 16 13 04 [0-3] 1f 10 8d ?? 00 00 01 13 ?? 06 11 ?? 16 1f 10 6f ?? 00 00 0a 26 1f 10 8d ?? 00 00 01 13 ?? 06 11 ?? 16 1f 10 6f }
        $s4 = { 72 ?? 00 00 70 20 e8 03 00 00 73 ?? 00 00 0a 0a 28 ?? 00 00 0a }
    condition:
        uint16(0) == 0x5A4D and filesize > 5KB and 3 of ($s*) 
}
