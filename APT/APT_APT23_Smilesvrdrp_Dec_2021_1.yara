rule APT_APT23_Smilesvrdrp_Dec_2021_1
{
   meta:
        description = "Detect the Smilesvrdrp backdoor"
        author = "Arkbird_SOLG"
        reference = "https://cyberworkx.in/2021/12/22/cyber-espionage-hackers-from-tropic-trooper-are-targeting-the-transportation-sector/"
        date = "2021-12-26"
        hash1 = "c6cac51035ef7df22c8ff3b5ba204721cdae97bc4728b0de68db1358c0c04035"
        tlp = "White"
        adversary = "APT23"
   strings:
        $s1 = { 83 c4 0c 8d 84 24 10 14 00 00 68 78 a3 41 00 68 58 17 43 00 68 d0 76 41 00 50 ff 15 7c 21 41 00 83 c4 10 8d 94 24 10 04 00 00 8d 8c 24 10 14 00 00 e8 30 ef ff ff 85 c0 0f 84 db 00 00 00 8d 8c 24 10 04 00 00 e8 ac ef ff ff 85 c0 0f 84 c7 00 00 00 68 ff 03 00 00 8d 84 24 15 0c 00 00 c6 84 24 14 0c 00 00 00 6a 00 50 e8 48 97 00 00 83 c4 0c 8d 84 24 10 0c 00 00 68 38 a3 41 00 68 58 1f 43 00 68 dc 76 41 00 68 00 04 00 00 50 e8 d4 10 00 00 83 c4 14 8d 84 24 10 0c 00 00 6a 00 50 8d 84 24 18 04 00 00 50 ff 15 54 20 41 00 83 }
        $s2 = { 25 25 53 79 73 74 65 6d 52 6f 6f 74 25 25 5c 53 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 25 73 }
        $s3 = { 8d 85 f8 ef ff ff 68 00 08 00 00 50 6a 00 ff 15 30 20 41 00 6a 00 68 80 00 00 10 6a 02 6a 00 6a 01 68 00 00 00 c0 8d 85 f8 f7 ff ff 50 ff 15 80 20 41 00 8b f0 83 fe ff 74 7c 68 ff 0f 00 00 8d 85 f9 df ff ff c6 85 f8 df ff ff 00 6a 00 50 e8 8f 9c 00 00 83 c4 0c 8d 85 f8 df ff ff 57 68 48 76 41 00 50 e8 a6 15 00 00 8d 8d f8 df ff ff c7 85 f4 df ff ff 00 00 00 00 83 c4 0c 8d 51 01 8d 64 }
        $s4 = { 68 78 76 41 00 33 c9 68 00 08 00 00 68 58 17 43 00 66 89 08 e8 7f 16 00 00 83 c4 0c c6 84 24 10 10 00 00 00 8d 84 24 11 10 00 00 68 ff 03 00 00 6a 00 50 e8 45 99 00 00 83 c4 0c 8d 84 24 10 10 00 00 68 24 a3 41 00 68 58 17 43 00 68 bc 76 41 00 68 00 04 00 00 50 e8 d1 12 00 00 8b 35 6c 21 41 }
    condition:
        uint16(0) == 0x5A4D and filesize > 30KB and 3 of ($s*) 
}
