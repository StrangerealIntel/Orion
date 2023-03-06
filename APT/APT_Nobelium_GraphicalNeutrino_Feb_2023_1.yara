rule APT_Nobelium_GraphicalNeutrino_Feb_2023_1 : apt nobelium graphicalneutrino
{
   meta:
        description = "Detect the graphicalneutrino loader used by BlueBravo (Recoded Future) aka Nobelium Group"
        author = "Arkbird_SOLG"
        reference = "https://go.recordedfuture.com/hubfs/reports/cta-2023-0127.pdf"
        date = "2023-01-29"
        hash1 = "1cffaf3be725d1514c87c328ca578d5df1a86ea3b488e9586f9db89d992da5c4"
        hash2 = "381a3c6c7e119f58dfde6f03a9890353a20badfa1bfa7c38ede62c6b0692103c"
        hash3 = "e957326b2167fa7ccd508cbf531779a28bfce75eb2635ab81826a522979aeb98"
        // ->  Added from https://twitter.com/felixaime/status/1632448523995103232
        tlp = "Clear"
        adversary = "Nobelium"
   strings:
        $s1 = { 48 83 ec 28 48 8b 05 [2] 00 00 8b 00 85 c0 75 47 48 c7 05 [2] 00 00 00 24 01 00 b9 00 24 01 00 e8 ?? a0 fe ff 48 89 05 [2] 00 00 48 85 c0 74 34 48 89 05 [2] 00 00 48 c7 00 00 24 01 00 48 c7 40 08 00 00 00 00 48 8d 0d b1 fe ff ff 48 83 c4 28 e9 [2] fc ff 48 8d 0d [2] 00 00 e8 ?? 12 fe ff eb ab 48 c7 05 [2] 00 00 00 00 00 00 48 c7 05 [2] 00 00 00 00 00 00 eb ca 90 90 48 83 ec 28 48 8b 05 [2] 00 00 c6 05 [2] 00 00 00 8b 00 85 c0 75 10 48 8d 0d a1 fe ff ff 48 83 c4 28 e9 [2] fc ff 48 8d 15 [2] fe ff 48 8d 0d [2] 00 00 e8 [2] fe ff }
        $s2 = { 48 c7 41 08 00 00 00 00 b9 3d 00 00 00 f3 ab 48 8d 7c 24 28 4c 89 e9 48 c7 44 24 2c 00 00 00 00 48 c7 44 24 34 00 00 00 00 48 89 fa c7 44 24 28 04 01 00 00 ff 15 [2] 04 00 4c 89 ea 4c 89 e1 e8 [2] 02 00 ba 5f 00 00 00 4c 89 e1 e8 [2] 02 00 8b 54 24 28 31 c0 39 c2 76 0b 41 c6 44 05 00 00 48 ff c0 eb f1 c7 44 24 28 04 01 00 00 49 89 f8 4c 89 ea b9 03 00 00 00 ff 15 [2] 04 00 4c 89 ea 4c 89 e1 e8 [2] 02 00 4c 89 e0 48 81 c4 30}
        $s3 = { c7 44 24 20 00 00 00 00 45 31 c9 45 31 c0 31 d2 48 8d 0d [2] 04 00 ff 15 [2] 04 00 49 89 c4 48 85 c0 0f 84 ?? 01 00 00 }
        $s4 = { 48 8d 0d [2] 03 00 e8 [2] 01 00 4c 89 ?? 4c 89 ?? e8 [2] ff ff 4c 8d ?? 24 ?? 00 00 00 4c 8d 05 [2] 03 00 4c 89 ?? 4c 89 ?? e8 ?? e4 02 00 4c 89 ?? e8 ?? ad 02 00 48 8b 8c 24 ?? 00 00 00 31 d2 ff 15 [2] 04 00 85 c0 75 10 4c 89 ?? 45 31 ?? e8 ?? ad 02 00 e9 ?? 04 00 00 48 b8 [8] c6 84 24 ?? 01 00 00 ?? 48 89 84 24 ?? 01 00 00 48 b8 [8] 48 89 84 24 ?? 01 00 00 8a 05 [2] 03 00 84 }
    condition:
        uint16(0) == 0x5A4D and filesize > 80KB and all of ($s*)
} 
