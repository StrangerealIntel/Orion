rule CRIM_FIN13_IPScanner_Jan_2022_1 : fin13 port scanner
{
    meta:
        description = "Detect a java Port Scanner used by the fin13 group (version 1.2)"
        author = "Arkbird_SOLG"
        date = "2022-01-06"
        reference = "https://f.hubspotusercontent30.net/hubfs/8776530/Sygnia-%20Elephant%20Beetle_Jan2022.pdf"
        hash1 = "61257b4ef15e20aa9407592e25a513ffde7aba2f323c2a47afbc3e588fc5fcaf"
        hash2 = "84ac021af9675763af11c955f294db98aeeb08afeacd17e71fb33d8d185feed5"
        tlp = "clean"
        adversary = "fin13"
    strings:
        $s1 = { 4d 61 69 6e 41 70 70 2e 63 6c 61 73 73 95 56 5b 50 1b d7 19 fe 8e 2e bb 92 bc 06 db 40 62 f9 92 38 36 b5 11 04 08 d8 f1 45 72 9c 82 af b2 05 76 01 13 63 d7 49 16 69 81 25 42 ab ae 56 2e a4 49 93 36 4e 1c dc 4b 9a 9b d3 dc 13 3b 2d 4d 6f d3 b8 33 c2 2d 9d 4c f3 d0 cb a4 4f 9d c9 4c fb d0 99 f6 29 d3 4e 66 3a 7d e9 43 fb 50 f7 3b bb 12 42 94 3e 04 83 f7 ec 7f ce ff 9f ef ff ce f7 ff 67 3f fc cf cf df 07 d0 85 1f a9 f0 09 a8 7d ba 99 eb c9 e7 55 04 04 d6 4c ea 17 f4 ce ac 9e 1b ef 3c 39 3a 69 a4 1d 81 48 5f cf 99 07 86 8e 0d 1c ee 39 24 20 92 02 a1 fd e9 ac 99 33 9d 03 02 fe 96 d8 b0 40 e0 a0 95 31 c2 10 58 a5 21 08 45 a0 3e 65 e6 8c fe e2 d4 a8 61 0f e9 a3 59 43 60 5d ca 4a eb d9 61 dd 36 e5 7b d9 a8 ec 77 c3 44 e0 c7 1a 0d 75 08 31 94 33 61 16 04 c2 a9 32 a8 04 4d 53 1c 0a dc d2 72 2e 55 05 37 e8 d8 66 6e 3c 11 1b 0e e3 16 ac 57 71 6b 0d f4 c1 99 82 63 4c 69 88 62 03 31 5a 45 66 d1 e4 39 9b 56 e7 29 7a 3a f4 37 f4 a9 44 }
        $s2 = { 50 6f 72 74 53 63 61 6e 6e 65 72 2e 63 6c 61 73 73 7d 55 6d 53 1b 55 14 7e 6e b2 61 c3 66 69 20 a4 20 a5 29 b4 d5 36 04 68 44 ea 1b 54 14 68 b1 d1 00 b5 01 14 b5 ea b2 d9 c0 96 b0 9b d9 6c a8 7c 74 ac ff c4 19 c6 8f 9d 91 c0 c8 8c 5f 9d f1 47 89 cf dd 04 a8 21 f8 61 cf bd f7 9c 7b 9e fb 9c 97 7b f7 ef 7f fe f8 13 c0 04 b6 54 84 04 62 4f 5c cf 2f 98 86 e3 58 9e 0a 45 20 f9 dc d8 35 b2 35 df 2e 67 97 37 aa 96 b7 6b 6c 94 2d 15 1d 02 89 c0 52 36 9c cd ec d3 9a e3 48 bd 40 87 6f 78 9b 96 4f 6b fe dc 5c f0 3d db d9 9c 16 88 96 3c 77 47 9e 20 20 72 72 b3 db 58 74 3c b0 1d db 9f 11 08 }
        $s3 = { 4f 62 73 65 72 76 65 72 4e 6f 74 69 66 69 65 72 2e 63 6c 61 73 73 6d 52 5b 6f 12 41 14 fe 06 28 0b eb 56 90 02 de eb d6 2b 50 ca 5a ef ba c6 07 4d 7c 22 b4 49 0d 89 8f 03 8c 38 64 d9 25 bb b3 8d fe 14 7f 86 46 69 a2 89 d1 57 7f 94 f1 cc 82 69 b8 3c cc 39 33 e7 7c e7 3b b7 f9 f3 f7 fb 4f 00 fb 78 66 20 c5 50 3c e8 45 22 3c 16 61 27 50 f2 9d 14 a1 81 0c 59 47 fc 98 3b 1e f7 87 ce 41 6f 24 fa ca 40 96 a1 94 58 63 25 3d e7 7f 14 43 26 14 d1 84 7c ed d3 90 23 15 4a 7f e8 32 64 9f 4b 5f aa 17 0c e9 5a bd 4b d0 57 c1 40 98 48 63 d3 42 1e 26 43 a1 2d 7d d1 89 c7 3d 11 be e1 3d 4f 68 9a a0 }
        $s4 = { 49 70 45 78 74 65 6e 64 65 72 2e 63 6c 61 73 73 8d 55 4b 6c 5b 45 14 3d 63 3f fb 7d 78 25 a9 13 27 84 86 36 90 92 d8 8e 63 37 29 38 d4 4e 53 9a 92 42 c0 4d 0a 29 29 fd 50 fa 6c bf a6 2f 75 6c d7 7e ae 5a 89 65 b6 48 6c 90 68 25 10 42 48 5e 54 95 80 85 53 51 04 1b 36 b0 66 c9 9e 3d 4b 16 2d 67 fc 49 9a da 91 b0 75 67 8e 67 ce bd 77 ee 67 c6 7f 3c fe e9 17 00 53 c8 a9 f0 08 18 8b a5 85 db ae 5d c8 d9 65 15 8a 40 ef ba 75 cb 8a e7 ad c2 5a 7c 39 b3 6e 67 5d 01 ff ac 53 70 dc 39 01 6f 28 bc 2a a0 9c 2a e6 6c 03 5e e8 26 7c f0 0b f4 a4 9d 82 bd 54 dd c8 d8 e5 73 56 26 6f 0b 04 d2 c5 ac 95 5f b5 ca 8e fc dd 5a 54 dc eb 4e 45 c0 4c ef 78 4c 09 68 76 }
    condition:
         uint16(0) == 0x4b50 and filesize > 5KB and all of ($s*)
}