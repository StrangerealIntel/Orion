rule APT_APT15_Ketrican_Jun_2023_1 : apt apt15 backdoor ketrican 
{
   meta:
        description = "Detect the Ketrican backdoor used by the apt15 group"
        author = "Arkbird_SOLG"
        reference = "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/flea-backdoor-microsoft-graph-apt15"
        date = "2023-06-21"
        hash1 = "858818cd739a439ac6795ff2a7c620d4d3f1e5c006913daf89026d3c2732c253"
        hash2 = "fd21a339bf3655fcf55fc8ee165bb386fc3c0b34e61a87eb1aff5d094b1f1476"
        tlp = "Clear"
        adversary = "APT15"
   strings:
        $s1 = { ff 76 10 b9 [2] 42 00 50 e8 [2] 00 00 6a 15 68 [2] 42 00 8d 8d 7c ef ff ff e8 [2] 00 00 51 8d 85 94 ef ff ff 50 68 [2] 42 00 51 8d 8d 7c ef ff ff e8 [2] ff ff 83 c4 10 84 c0 0f 84 ?? 03 00 00 8b 8d 98 ef ff ff b8 ab aa aa 2a 2b 8d 94 ef ff ff f7 e9 c1 fa 02 8b c2 c1 e8 1f }
        $s2 = { 83 c4 0c 8d 85 ?? fe ff ff 68 00 01 00 00 6a 00 50 e8 [2] 00 00 83 c4 0c 8d 85 ?? fe ff ff 68 00 01 00 00 50 ff 15 ?? f1 41 00 8d 85 ?? fe ff ff 8d 50 01 8a 08 40 84 c9 75 f9 2b c2 50 8d 85 ?? fe ff ff 50 56 e8 [2] 00 00 83 c4 0c 8d 85 ?? fe ff ff 50 ff 15 }
        $s3 = { 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 56 c6 85 c8 ee ff ff 00 ff 15 ?? f1 41 00 85 c0 0f 85 6c 02 00 00 8d 85 84 ef ff ff 0f 57 c0 50 0f 11 85 84 ef ff ff ff 15 ?? f1 41 00 85 c0 0f 84 [2] 00 00 8b 85 88 ef ff ff 85 c0 0f 84 38 01 00 00 83 3d [2] 42 00 08 8d 8d 48 ef ff ff 51 89 85 20 ef ff ff 8d 8d 18 ef ff ff b8 [2] 42 00 c7 85 18 ef ff ff 03 00 00 00 0f 43 05 [2] 42 00 0f 57 c0 51 50 ff 35 [2] 42 00 c7 85 1c ef ff ff 01 00 00 00 c7 85 2c ef ff ff 01 00 00 00 c7 85 28 ef ff ff 00 00 00 00 c7 85 24 ef ff ff 00 00 00 00 66 0f d6 85 48 ef ff ff c7 85 50 ef ff }
   condition:
       uint16(0) == 0x5A4D and filesize > 60KB and all of ($s*)
}
