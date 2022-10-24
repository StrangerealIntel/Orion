rule APT_APT23_USBFerry_May_2020_2
{
   meta:
        description = "Detect the USBFerry implant (Packed x64)"
        author = "Arkbird_SOLG"
        reference = "https://documents.trendmicro.com/assets/Tech-Brief-Tropic-Trooper-s-Back-USBferry-Attack-Targets-Air-gapped-Environments.pdf"
        date = "2020-05-14"
        hash1 = "905fcf0f574bf104a62c7a5c91cd95fbacb06bf3fbcdcb38320113394c7386d7"
        tlp = "Clear"
        adversary = "APT23"
   strings:
        $s1 = { b9 45 29 e5 35 81 f1 ef 21 e5 35 4c 03 c1 49 ff c8 41 80 30 45 41 80 00 88 41 80 30 31 41 80 28 ab 48 ff c9 9c 48 c1 2c 24 06 48 f7 14 24 48 83 24 24 01 50 52 48 b8 7a ff ff ff ff ff ff ff 48 f7 64 24 10 48 8d 15 66 0b b5 47 48 8d 94 02 e3 f4 4a b8 48 89 54 24 10 5a 58 48 8d 64 24 08 ff }
        $s2 = { bd e0 02 00 00 00 00 00 00 00 00 00 00 00 00 00 cb e0 02 00 00 00 00 00 00 00 00 00 00 00 00 00 e0 e0 02 00 00 00 00 00 ef e0 02 00 00 00 00 00 00 e1 02 00 00 00 00 00 0f e1 02 00 00 00 00 00 00 00 00 00 00 00 00 00 55 53 45 52 33 32 2e 44 4c 4c }
        $s3 = { 26 74 99 ae 8b c1 c1 74 db 3c ef 1d 27 27 eb 7b 33 f7 2d 7c 84 b8 f6 dc 65 46 ac e0 d3 7a 80 94 97 ed 8b 94 11 e5 31 14 38 7a a9 45 15 7f 34 c3 9a 11 db 5c e4 ec df f0 2e 8b 76 f4 11 28 09 d1 bf 18 54 5e d0 f7 2b 20 7b bb 05 32 b4 79 c4 72 74 5f 96 64 f4 6b b0 73 f4 8b 75 07 f2 8b d4 86 1e 84 8b 42 }
        $s4 = { da 94 29 5a d3 eb a3 8c 43 8b a7 6b aa 15 33 87 5a b7 5f 88 76 32 b7 f0 05 8a 93 dd 66 55 98 13 2a 45 96 62 35 ae e4 60 2a 84 72 d1 35 ab b4 b6 6b 33 b4 e4 a8 35 fc c6 0c 41 8c 74 c7 bd 05 d0 6c 5f 83 7c a4 3b c6 41 f0 e0 1d 5b 65 a4 fd a5 7b 42 b9 79 f3 70 00 8c db e4 8b b0 9f a4 56 32 b4 00 3b 95 }
    condition:
        uint16(0) == 0x5A4D and filesize > 30KB and 3 of ($s*) 
}
