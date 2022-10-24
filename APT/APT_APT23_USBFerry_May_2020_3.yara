rule APT_APT23_USBFerry_May_2020_3
{
   meta:
        description = "Detect the USBFerry implant (unpacked x86)"
        author = "Arkbird_SOLG"
        reference = "https://documents.trendmicro.com/assets/Tech-Brief-Tropic-Trooper-s-Back-USBferry-Attack-Targets-Air-gapped-Environments.pdf"
        date = "2020-05-14"
        hash1 = "5f0e14bbb0700318a11e43cb6b3e6ef82e8d0cc01cf89660a3e9bab20af033fa"
        hash2 = "872b39f0a673183dee8461b3592f3c4ab7f0e10ed3e00eed59112b517f9e6b89"
        hash3 = "d283cbeee4c21ff2d5983af7fdbd097c84c56e9252cbd5fb33cb73f8e0bbf323"
        tlp = "Clear"
        adversary = "APT23"
   strings:
        $s1 = { 57 8d [6-7] 00 10 00 00 51 e8 [2] 00 00 68 ff 03 00 00 8d [3-5] 53 52 88 [3-5] e8 [2] 00 00 8d [5-6] 50 56 8d }
        $s2 = { 83 c4 0c 68 [4] 8d ?? 24 [2] 00 00 }
        $s3 = { 53 e8 [2] ff ff 59 50 ff 15 [3] 10 85 c0 75 0b ff 15 [3] 10 89 45 e4 eb 04 83 65 e4 00 83 7d e4 00 74 19 e8 [2] ff ff 8b 4d e4 89 08 e8 [2] ff ff c7 00 09 00 00 00 83 4d e4 ff c7 45 fc fe ff ff ff e8 0c 00 00 00 8b 45 e4 e8 }
        $s4 = { 53 8d 95 f8 db ff ff 52 8d 85 fc fb ff ff 50 89 9d f8 db ff ff ff 15 14 [2] 10 50 8d 8d fc fb ff ff 51 56 ff 15 [3] 10 56 ff 15 [3] 10 68 ff 07 00 00 8d 95 fd eb ff ff 53 52 88 9d fc eb ff ff e8 [2] 00 00 83 c4 0c 68 00 08 00 00 8d 85 fc eb ff ff 50 ff 15 [3] 10 8d 85 fc eb ff ff 48 8a 48 01 40 3a cb 75 f8 8b 0d [3] 10 8b 15 [3] 10 89 08 8b 0d [3] 10 89 50 04 68 00 10 00 00 8d 95 fc db ff ff 53 52 89 48 08 e8 [2] 00 00 8d 85 fc f3 ff ff 50 8d 8d fc eb ff ff 51 8d 95 fc db ff ff 68 [3] 10 52 e8 [2] 00 00 83 c4 1c 53 8d 85 fc db ff ff 50 ff 15 [3] 10 68 a0 0f 00 00 ff 15 [3] 10 8d 8d fc f3 ff ff 51 ff 15 [3] 10 8b 4d fc 5f 5e }
    condition:
        uint16(0) == 0x5A4D and filesize > 30KB and all of ($s*) 
}
