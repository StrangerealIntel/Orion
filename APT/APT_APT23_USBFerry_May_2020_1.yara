rule APT_APT23_USBFerry_May_2020_1
{
   meta:
        description = "Detect the USBFerry implant (Unpacked x64)"
        author = "Arkbird_SOLG"
        reference = "https://documents.trendmicro.com/assets/Tech-Brief-Tropic-Trooper-s-Back-USBferry-Attack-Targets-Air-gapped-Environments.pdf"
        date = "2020-05-14"
        hash1 = "32299feded258d78323a7a23acd5463d908c3fbbd46842817b53ab9116587d64"
        hash2 = "a0e8c1ece844f18876c951b4360cef1c8e63d270ab5a8346e4a81cba36795838"
        hash3 = "90496241ffdbdd1592d0b8aba76d6f8616fc1093623c0d2c2a4fecc4199293cb"
        tlp = "Clear"
        adversary = "APT23"
   strings:
        $s1 = { 00 00 48 8d 48 01 48 8d 15 [3] 00 e8 ?? 08 00 00 85 c0 75 e5 4c 8d 05 [3] 00 33 d2 33 c9 ff 15 [2] 00 00 48 89 05 [3] 00 ff 15 [2] 00 00 3d b7 00 00 00 0f 84 [2] 00 00 83 f8 }
        $s2 = { 8b c8 8b d8 e8 [2] 00 00 44 8b c3 33 d2 48 8b c8 48 8b f8 e8 [2] 00 00 44 8b 44 24 78 4c 8d 8c 24 80 00 00 00 48 8b d7 48 8b cd ff 15 [3] 00 85 c0 74 4f 44 8b 84 24 80 00 00 00 4c 8d 8c 24 88 00 00 00 48 8b d7 48 8b ce 44 89 a4 24 88 00 00 00 4c 89 64 24 20 ff 15 [3] 00 48 8b cf e8 [2] 00 00 48 8d 54 24 78 45 33 c9 45 33 c0 48 8b cd ff 15 [3] 00 85 c0 0f 85 71 ff ff ff eb 08 48 8b cf e8 [2] 00 00 48 8b 5c 24 50 48 8b 7c 24 40 48 8b ce ff 15 [3] 00 48 8b ce ff 15 [3] 00 48 8b 74 24 48 b8 01 00 00 00 48 83 c4 }
        $s3 = { 48 8d 8d 50 1b 00 00 89 5c 24 40 ff 15 [2] 00 00 4c 8d 4c 24 40 48 8d 95 50 1b 00 00 48 8b cf 44 8b c0 48 89 5c 24 20 ff 15 [3] 00 48 8b cf ff 15 [3] 00 48 8d 4c 24 50 e8 [2] ff ff 85 c0 74 0f 48 8d 8d 50 13 00 00 33 d2 ff 15 [3] 00 b9 a0 0f 00 00 ff 15 [3] 00 48 8d 4c 24 50 ff 15 [3] 00 48 8d 8d 50 13 00 00 ff 15 [3] 00 b8 01 00 00 00 48 8b 8d 50 2b }
        $s4 = { 41 b8 ff 07 00 00 48 8d 8c 24 81 09 00 00 e8 [2] 00 00 45 33 c9 45 8d 46 1a 48 8d 94 24 80 09 00 00 33 c9 ff 15 [2] 00 00 48 8d bc 24 80 09 00 00 33 c0 48 83 c9 ff f2 ae 48 8b 05 [3] 00 48 89 47 ff 33 d2 48 8d 8c 24 80 09 00 00 ff 15 [2] 00 00 44 88 b4 24 80 25 00 00 33 d2 41 b8 ff 07 00 00 48 8d 8c 24 81 25 00 00 e8 [2] 00 00 48 8d bc 24 80 25 00 00 33 c0 48 83 c9 ff f2 ae 48 }
    condition:
        uint16(0) == 0x5A4D and filesize > 30KB and all of ($s*) 
}

