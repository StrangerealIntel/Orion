rule MAL_DeimosC2_Beacon_Nov_2022_1 : deimosc2 beacon x64
{
   meta:
        description = "Detect the beacon used in the DeimosC2 framework (x64 version)"
        author = "Arkbird_SOLG"
        reference = "https://www.trendmicro.com/en_us/research/22/k/deimosc2-what-soc-analysts-and-incident-responders-need-to-know.html"
        date = "2022-11-08"
        hash1 = "4f069ec1dc6e88a2b4e1c50a8dda6a7935f91424724499b41ff1c3a9f87b143c"
        hash2 = "21827cb6d8409ddea5097384d86f3004f5ec4ebe387a9340d8f3443598bdd2af"
        hash3 = "dbc5b2946b58deb1c40d787e3c5386b9020086b5d01dbbfbaccc44b322aca68c"
        hash4 = "6f3394a5980ddbc28c7e889c636cddabd48a710588a5c10427d10a19d07b1c0a"
        tlp = "Clear"
        adversary = "-"
   strings:
        $s1 = { 48 83 ec 70 48 89 6c 24 68 48 8d 6c 24 68 48 c7 44 24 30 00 00 00 00 48 c7 44 24 28 00 00 00 00 48 8b 05 a7 [2] 00 48 89 04 24 48 c7 44 24 08 ff ff ff ff 48 8d 44 24 30 48 89 44 24 10 48 8d 44 24 28 48 89 44 24 18 e8 59 18 00 00 48 83 7c 24 20 00 74 35 31 c0 31 c9 eb 24 48 89 ca 48 89 c1 bb 01 00 00 00 48 d3 e3 48 23 5c 24 30 48 8d 72 01 48 85 db 48 0f 45 d6 48 ff c0 48 89 d1 48 83 f8 40 7c d6 48 85 c9 75 3e 0f 57 c0 0f 11 44 24 38 0f 11 44 24 48 0f 11 44 24 58 48 8b 05 0b [2] 00 48 89 04 24 48 8d 44 24 38 48 89 44 24 08 e8 30 17 00 00 8b 44 24 58 89 44 24 78 48 8b 6c }
        $s2 = { 48 8b 05 a0 [2] 00 48 8d 0d [3] 00 48 89 04 24 48 89 4c 24 08 48 c7 44 24 10 08 02 00 00 e8 12 22 00 00 48 8b 44 24 18 48 85 c0 74 33 48 3d 08 02 00 00 77 2b 48 8d 1d [3] 00 c6 04 03 5c 48 ff c0 48 89 05 [3] 00 e9 d6 fe ff ff 31 c0 e8 9f 2e 03 00 ba 09 02 00 00 e8 c5 2e 03 00 48 8d 05 [3] 00 48 89 04 24 48 c7 44 24 }
        $s3 = { 48 8b 15 36 [2] 00 48 89 14 24 48 89 4c 24 08 48 89 44 24 10 48 c7 44 24 18 00 10 00 00 48 c7 44 24 20 04 00 00 00 e8 e1 a6 01 00 48 83 7c 24 28 00 40 0f 94 c6 48 8b 44 24 38 48 8b 4c 24 48 48 8b 54 24 68 48 8b 5c 24 40 e9 61 ff ff ff 48 8b 6c 24 50 48 83 c4 58 c3 48 8b 6c 24 50 48 83 }
        $s4 = { 48 81 ec b0 00 00 00 48 89 ac 24 a8 00 00 00 48 8d ac 24 a8 00 00 00 48 c7 44 24 48 00 00 00 00 48 8b 05 12 [2] 00 48 89 04 24 48 c7 44 24 08 ff ff ff ff 48 c7 44 24 10 fe ff ff ff 48 c7 44 24 18 ff ff ff ff 48 8d 44 24 48 48 89 44 24 20 0f 57 c0 0f 11 44 24 28 48 c7 44 24 38 02 00 00 00 e8 fb 05 00 00 65 48 8b 04 25 28 00 00 00 48 8b 80 00 00 00 00 48 8b 40 30 48 89 84 24 98 00 00 00 84 00 48 8d 88 10 03 00 00 48 89 8c 24 a0 00 00 00 48 89 0c 24 e8 45 81 fd ff 48 8b 44 24 48 48 8b 8c 24 98 00 00 00 48 89 81 18 03 00 00 48 8b 84 24 a0 00 00 00 48 89 04 24 e8 10 83 fd ff 0f 57 c0 0f 11 44 24 68 0f 11 44 24 78 0f 11 84 24 88 00 00 00 48 8b 05 84 [2] 00 48 89 04 24 48 8d 44 24 68 48 89 44 24 08 48 8d 44 24 68 48 89 44 24 10 48 c7 44 24 18 30 00 00 00 e8 de 03 00 00 48 83 7c }
   condition:
       uint16(0) == 0x5A4D and filesize > 300KB and all of ($s*)
}
