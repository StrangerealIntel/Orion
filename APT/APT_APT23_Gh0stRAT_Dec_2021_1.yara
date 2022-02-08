rule APT_APT23_Gh0stRAT_Dec_2021_1
{
   meta:
        description = "Detect the Gh0st RAT version of APT23"
        author = "Arkbird_SOLG"
        reference = "https://cyberworkx.in/2021/12/22/cyber-espionage-hackers-from-tropic-trooper-are-targeting-the-transportation-sector/"
        date = "2021-12-26"
        hash1 = "996aa9c937b610efd1ab5c0ab173fc9fa78a70b423a193c3e2b505519bde7807"
        hash2 = "7e72ee1052b018250810e41ac01065ebd833293ecfc363415b7d19dd31734d49"
        tlp = "White"
        adversary = "APT23"
   strings:
        $s1 = { b9 3f 00 00 00 33 c0 8d bc 24 c5 00 00 00 c6 84 24 c4 00 00 00 00 f3 ab 8d 8c 24 ec 02 00 00 8d 94 24 c4 00 00 00 66 ab 51 68 c4 69 41 00 52 aa ff d5 8b 35 f0 f0 40 00 83 c4 0c 8d 84 24 c4 00 00 00 6a 00 50 ff d6 68 b8 0b 00 00 ff d3 b9 40 00 00 00 33 c0 8d bc 24 c4 00 00 00 68 94 69 41 00 f3 ab 8d 8c 24 c8 00 00 00 51 ff d5 83 c4 08 33 db 8d 94 24 c4 00 00 00 53 52 ff d6 b9 40 00 00 00 33 c0 8d bc 24 c4 00 00 00 68 1c 69 41 00 f3 ab 8d 84 24 }
        $s2 = { 83 ec 08 33 c0 56 89 44 24 05 8d 4c 24 04 66 89 44 24 09 c6 44 24 04 00 50 50 50 51 6a 04 68 ?? 6a 41 00 68 ?? 6a 41 00 68 02 00 00 80 88 44 24 2b e8 [2] ff ff 8d 54 24 24 52 ff 15 f8 f1 40 00 83 c4 24 8b f0 8d 44 24 04 50 }
        $s3 = { 8b 15 6c 5f 41 00 52 68 4c 5f 41 00 68 30 6a 41 00 ff 15 e8 f1 40 00 bf 28 6a 41 00 83 c9 ff 33 c0 83 c4 0c f2 ae f7 d1 2b f9 68 18 6a 41 00 8b c1 8b f7 bf 24 5f 41 00 53 c1 e9 02 f3 a5 8b c8 33 c0 83 e1 03 50 f3 a4 bf 10 6a 41 00 83 c9 ff f2 ae f7 d1 2b f9 8b d1 8b f7 bf 34 5f 41 00 c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4 8b 35 e4 f0 40 00 ff d6 8b 3d 9c f0 40 00 }
        $s4 = { 8d 4c 24 14 e8 ?? 7b 00 00 8d 44 24 14 50 51 8b cc 89 64 24 20 68 04 6a 41 00 e8 ?? 7b 00 00 e8 ?? 15 00 00 83 c4 08 85 c0 75 3c b9 3f 00 00 00 8d bc 24 c5 00 00 00 88 84 24 c4 00 00 00 f3 ab 66 ab 8d 8c 24 c4 00 00 00 51 68 00 01 00 00 aa ff 15 e8 f0 40 00 8d 94 24 c4 }
    condition:
        uint16(0) == 0x5A4D and filesize > 30KB and all of ($s*) 
}
