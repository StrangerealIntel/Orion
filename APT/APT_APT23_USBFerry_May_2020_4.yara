rule APT_APT23_USBFerry_May_2020_4
{
   meta:
        description = "Detect a variant of USBFerry implant (unpacked x86)"
        author = "Arkbird_SOLG"
        reference = "https://documents.trendmicro.com/assets/Tech-Brief-Tropic-Trooper-s-Back-USBferry-Attack-Targets-Air-gapped-Environments.pdf"
        date = "2020-05-14"
        hash1 = "1f383eb5f614669404ef00d693510f40ca87c30204ef269a0a19aa4564942444."
        tlp = "White"
        adversary = "APT23"
   strings:
        $s1 = { 57 8d [6-7] 00 10 00 00 51 e8 ?? ?? 00 00 68 ff 03 00 00 8d [3-5] 53 52 88 [3-5] e8 ?? ?? 00 00 8d [5-6] 50 56 8d }
        $s2 = { 83 c4 0c 68 [4] 8d ?? 24 [2] 00 00 }
        $s3 = { e8 ?? ?? ff ff 59 50 ff 15 ?? ?? ?? 10 85 c0 75 0b ff 15 ?? ?? ?? 10 89 45 e4 eb ?? ?? ?? e4 }
        $s4 = { 53 8d 54 24 10 52 8d 44 24 18 50 89 5c 24 18 ff 15 14 20 01 10 50 8d 4c 24 1c 51 56 ff 15 48 20 01 10 56 ff 15 c8 20 01 10 68 ff 07 00 00 8d 94 24 15 0c 00 00 53 52 88 9c 24 1c 0c 00 00 e8 a6 89 00 00 83 c4 0c 68 00 08 00 00 8d 84 24 14 0c 00 00 50 ff 15 64 20 01 10 8d 84 24 10 0c 00 00 48 8a 48 01 40 3a cb 75 f8 8b 0d dc 36 01 10 8b 15 e0 36 01 10 89 08 8b 0d e4 36 01 10 89 50 04 68 00 10 00 00 8d 94 24 14 14 00 00 53 52 89 48 08 e8 53 89 00 00 8d 84 24 1c 04 00 00 50 8d 8c 24 20 0c 00 00 51 8d 94 24 24 14 00 00 68 e8 36 01 10 52 e8 03 25 00 00 83 c4 1c 53 8d 84 24 14 14 00 00 50 ff 15 c4 20 01 10 68 a0 0f 00 00 ff 15 58 20 01 10 8d 8c 24 10 04 00 00 51 ff 15 d0 20 01 10 8b 8c 24 10 24 00 00 5f 5e 5b 33 cc b8 01 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and filesize > 30KB and all of ($s*) 
}
