rule APT_APT23_Smilesvr_Dec_2021_1
{
   meta:
        description = "Detect the Smilesvr backdoor"
        author = "Arkbird_SOLG"
        reference = "https://cyberworkx.in/2021/12/22/cyber-espionage-hackers-from-tropic-trooper-are-targeting-the-transportation-sector/"
        date = "2021-12-26"
        hash1 = "507b0280105da31739159703e418e3d1b1e6e6817362bf69e2da3c0b305af605"
        hash2 = "97e9bf8032e11bb618a77fbe92489e972b0c92e2e30b26f594f6129ee1cec987"
        hash3 = "c6f17d39905d2006020c326c13bb514a66bccc5a42d533aade00e09456ca5dec"
        tlp = "White"
        adversary = "APT23"
   strings:
        $s1 = { 81 ec 98 01 00 00 a1 [2] 01 10 33 c5 89 45 fc 8d 85 68 fe ff ff 50 68 02 01 00 00 ff 15 [3] 10 85 c0 75 55 6a 14 68 [2] 01 10 ff 15 [3] 10 85 c0 75 3e 68 [2] 01 10 ff 15 [3] 10 8b 40 0c 8b 00 ff 30 ff 15 [3] 10 50 6a 10 68 [2] 01 10 e8 [2] 00 00 83 c4 0c ff 15 [3] 10 33 c0 8b 4d fc }
        $s2 = { a1 10 e8 [3] 00 83 c4 0c 0f b7 [3] a1 10 [3] a1 10 0f b7 }
        $s3 = { 57 e8 [4] 59 50 ff 15 [3] 10 85 c0 75 }
        $s4 = { 43 4d 44 20 ( 72 65 61 64 79 | 63 6c 6f 73 65 ) 20 5e 5f 5e }
    condition:
        uint16(0) == 0x5A4D and filesize > 30KB and 3 of ($s*) 
}
