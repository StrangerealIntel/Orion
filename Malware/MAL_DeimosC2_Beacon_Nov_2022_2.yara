rule MAL_DeimosC2_Beacon_Nov_2022_2 : deimosc2 beacon x86
{
   meta:
        description = "Detect the beacon used in the DeimosC2 framework (x86 version)"
        author = "Arkbird_SOLG"
        reference = "https://www.trendmicro.com/en_us/research/22/k/deimosc2-what-soc-analysts-and-incident-responders-need-to-know.html"
        date = "2022-11-08"
        hash1 = "29305f74260d56f94a80d514505dbef949b0e6fae7989a9cd84e956ec4f6cffe"
        hash2 = "980b4076a9571ef2c1ef0328ce63074f22adeb29ef1001f328783ca5783979cc"
        hash3 = "a325c7729d39e5530b2c0804cd28b4dfb1d7560736ae5cbc7631fa5949cf7940"
        hash4 = "8c6ab7a051eedf9f119778bdc71cd96a40f52101657881e84262237083ba4a51"
        tlp = "Clear"
        adversary = "-"
   strings:
        $s1 = { 83 ec 40 c7 44 24 18 00 00 00 00 c7 44 24 14 00 00 00 00 8b 05 84 [2] 00 89 04 24 c7 44 24 04 ff ff ff ff 8d 44 24 18 89 44 24 08 8d 44 24 14 89 44 24 0c e8 b1 15 00 00 8b 44 24 10 85 c0 74 32 31 c0 31 c9 eb 03 40 89 d1 83 f8 20 7d 20 19 d2 89 cb 89 c1 bd 01 00 00 00 d3 e5 21 d5 23 6c 24 18 85 ed 74 05 8d 53 01 eb dc 89 da eb d8 85 c9 75 2d 8d 7c 24 1c 31 c0 e8 a3 cc 02 00 8b 0d 74 [2] 00 89 0c 24 8d 4c 24 1c 89 4c 24 04 e8 d6 14 00 00 8b 4c 24 30 89 4c 24 44 83 c4 }
        $s2 = { 8b 05 78 [2] 00 8d 0d [3] 00 89 04 24 89 4c 24 04 c7 44 24 08 08 02 00 00 e8 f0 1d 00 00 8b 44 24 0c 85 c0 74 2e 3d 08 02 00 00 77 27 8d 1d [3] 00 c6 04 03 5c 40 89 05 [3] 00 e9 0b ff ff ff 31 c0 e8 24 d3 02 00 ba 09 02 00 00 e8 4a d3 02 00 8d 05 [2] 77 00 89 04 24 c7 44 24 }
        $s3 = { 8b 15 38 [2] 00 89 14 24 89 4c 24 04 89 44 24 08 c7 44 24 0c 00 10 00 00 c7 44 24 10 04 00 00 00 e8 32 9c 01 00 8b 44 24 14 85 c0 87 dd 0f 94 c3 87 dd 8b 44 24 18 8b 4c 24 24 8b 54 24 30 8b 5c 24 1c e9 73 ff ff ff 83 c4 28 c3 83 c4 28 c3 e8 d3 dd 01 00 8d 05 [3] 00 89 04 24 c7 44 24 04 19 00 00 00 e8 5d e6 01 00 8b 44 24 18 89 04 24 c7 44 24 04 00 00 00 00 e8 59 e3 01 00 8d 05 [3] 00 89 04 24 c7 44 24 04 19 00 00 00 e8 33 e6 01 00 8b 44 24 20 89 04 24 c7 44 24 04 00 00 00 }
        $s4 = { 83 ec 58 c7 44 24 24 00 00 00 00 8b 05 9c [2] 00 89 04 24 c7 44 24 04 ff ff ff ff c7 44 24 08 fe ff ff ff c7 44 24 0c ff ff ff ff 8d 44 24 24 89 44 24 10 c7 44 24 14 00 00 00 00 c7 44 24 18 00 00 00 00 c7 44 24 1c 02 00 00 00 e8 89 04 00 00 64 8b 05 14 00 00 00 8b 80 00 00 00 00 8b 40 18 89 44 24 50 84 00 8d 88 b8 01 00 00 89 4c 24 54 89 0c 24 e8 91 ab fd ff 8b 44 24 24 8b 4c 24 50 89 81 bc 01 00 00 8b 44 24 54 89 04 24 e8 57 ad fd ff 8d 7c 24 34 31 c0 e8 75 ba 02 00 8b 05 30 [2] 00 89 04 24 8d 44 24 34 89 44 24 04 8d 44 24 34 89 44 24 08 c7 44 24 0c 1c 00 00 00 e8 16 03 00 00 8b 44 }
   condition:
       uint16(0) == 0x5A4D and filesize > 300KB and all of ($s*)
}
