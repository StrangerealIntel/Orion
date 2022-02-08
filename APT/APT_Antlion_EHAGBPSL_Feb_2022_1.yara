rule APT_Antlion_EHAGBPSL_Feb_2022_1
{
   meta:
        description = "Detect the EHAGBPSL implant"
        author = "Arkbird_SOLG"
        reference = "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/china-apt-antlion-taiwan-financial-attacks"
        date = "2022-02-04"
        hash1 = "e968e0d7e62fbc36ad95bc7b140cf7c32cd0f02fd6f4f914eeb7c7b87528cfe2"
        hash2 = "55636c8a0baa9b57e52728c12dd969817815ba88ec8c8985bd20f23acd7f0537"
        tlp = "White"
        adversary = "Antlion"
   strings:
        $s1 = { 66 89 0a 48 8d 54 24 30 48 2b d7 48 03 d7 40 38 32 75 f8 0f b7 0d [2] 01 00 66 89 0a 48 8d 4c 24 30 48 2b cf 48 03 cf 40 38 31 75 f8 48 8d 54 24 30 66 89 01 48 2b d7 48 03 d7 40 38 32 75 f8 0f b7 0d [2] 01 00 66 89 0a 48 8d 4c 24 30 48 2b cf 48 03 cf 40 38 31 75 f8 66 89 01 3b df 75 32 48 8d 54 24 30 48 8d 8d 30 05 00 00 e8 [2] 00 00 85 c0 75 1d 48 89 74 24 28 4c 8d 05 ?? f9 ff ff 4c 8b cf 89 74 24 20 33 d2 33 c9 ff 15 [2] 01 00 8b c7 48 8b 8d 30 07 00 00 48 33 }
        $s2 = { 48 8b 03 48 63 08 48 8b d1 48 8b c1 48 c1 f8 06 4c 8d 05 08 ?? 01 00 83 e2 3f 48 c1 e2 06 49 8b 04 c0 f6 44 10 38 01 74 24 e8 3d ff ff ff 48 8b c8 ff 15 [2] 00 00 33 db 85 c0 75 1e e8 c9 ac ff ff 48 8b d8 ff 15 [2] 00 00 89 03 e8 d9 ac ff ff c7 00 09 00 00 00 83 cb ff 8b 0f e8 29 fe ff ff 8b c3 48 }
        $s3 = { 48 83 ec 28 e8 cb 03 00 00 b0 01 48 83 c4 28 c3 40 53 48 83 ec 20 ff 15 [2] 00 00 48 85 c0 74 13 48 8b 18 48 8b c8 e8 9c 34 00 00 48 8b c3 48 85 db 75 ed 48 83 }
        $s4 = { 0f b7 06 48 83 c6 02 66 83 f8 0a 75 10 83 47 08 02 b9 0d 00 00 00 66 89 0b 48 83 c3 02 66 89 03 48 83 c3 02 48 8d 84 24 3e 14 00 00 48 3b d8 72 ca 48 83 64 24 20 00 48 8d 44 24 40 48 2b d8 4c 8d 4c 24 30 48 d1 fb 48 8d 54 24 40 03 db 49 8b ce 44 8b c3 ff 15 [2] 00 00 85 c0 74 12 8b 44 24 30 01 47 04 3b c3 72 0f }
    condition:
        uint16(0) == 0x5A4D and filesize > 30KB and all of ($s*) 
}
