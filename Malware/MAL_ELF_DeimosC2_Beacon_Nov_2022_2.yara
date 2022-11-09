rule MAL_ELF_DeimosC2_Beacon_Nov_2022_2 : deimosc2 beacon x86
{
   meta:
        description = "Detect the linux beacon used in the DeimosC2 framework (x86 version)"
        author = "Arkbird_SOLG"
        reference = "https://www.trendmicro.com/en_us/research/22/k/deimosc2-what-soc-analysts-and-incident-responders-need-to-know.html"
        date = "2022-11-08"
        hash1 = "046bc639e73a8f33fc580d20392b28fe261d08453b23d20f45d5ced7ae6b37d9"
        hash2 = "82aa04f8576ea573a4772db09ee245cab8eac7ff1e7200f0cc960d8b6f516e92"
        hash3 = "da76dc5c608f5f75a8bbb86e13eee6bb575a2305ca53036e8cebe0e3755a3982"
        tlp = "Clear"
        adversary = "-"
   strings:
        $s1 = { 83 ec 24 65 8b 05 00 00 00 00 8b 80 fc ff ff ff 89 44 24 1c c7 05 [3] 08 10 27 00 00 8d 0d [3] 08 84 01 90 8b 0d [3] 08 89 0d [3] 08 e8 a2 6f 01 00 e8 fd 26 01 00 e8 f8 67 fd ff 90 8d 05 [3] 08 89 04 24 c7 44 24 04 04 00 00 00 c7 44 24 08 04 00 00 00 e8 e9 9e ff ff 8b 44 24 1c 8b 48 18 89 0c 24 e8 3a 04 00 00 e8 05 fe ff ff e8 c0 08 fd ff e8 2b 6d 01 00 e8 86 0b 02 00 e8 b1 54 fd ff 8b 44 24 1c 8b 48 18 84 01 c7 04 24 02 00 00 00 c7 44 24 04 00 00 00 00 83 c1 44 89 4c 24 08 c7 44 24 0c 08 00 00 00 e8 85 8d 02 00 8b 44 24 1c 8b 40 18 8b 48 44 8b 40 48 89 0d [3] 08 89 05 [3] 08 e8 d7 b8 00 00 90 e8 e1 b9 00 00 e8 bc c1 00 00 e8 e7 2a fe ff e8 c2 8c 02 00 8b 44 24 04 8b 0c 24 89 0d [3] 08 89 05 [3] 08 8b 05 [3] 08 89 44 24 10 8d 0d [2] 3b 08 89 0c 24 c7 44 24 04 0a 00 00 00 e8 ff 2f fd ff 8b 44 24 0c 8b 4c 24 08 89 0c 24 89 44 24 04 e8 bb 60 01 00 8b 44 24 08 0f b6 }
        $s2 = { 24 8b 44 24 2c 83 c0 00 89 44 24 10 8b 54 24 24 89 14 24 8d 15 [2] 3b 08 89 54 24 04 c7 44 24 08 19 00 00 00 e8 6e d0 ff ff c7 44 24 14 00 00 00 00 c7 44 24 18 00 00 00 00 c7 44 24 1c 00 00 00 00 66 c7 44 24 20 00 00 8b 44 24 10 89 44 24 14 8b 44 24 2c 83 c0 00 8b 44 24 28 83 d0 00 89 44 24 18 c6 44 24 20 01 8b 44 24 30 89 44 24 1c c6 44 24 21 03 8d 05 [3] 08 89 04 24 8d 44 24 14 89 44 24 04 e8 cd 83 fd ff 8b 44 24 0c 8b 4c 24 08 89 0c 24 }
        $s3 = { 81 ec ac 02 00 00 b8 00 00 00 00 89 84 24 a8 02 00 00 c6 44 24 67 00 c7 84 24 d4 02 00 00 00 00 00 00 c7 84 24 d8 02 00 00 00 00 00 00 c7 84 24 dc 02 00 00 00 00 00 00 8d 84 24 bc 02 00 00 89 04 24 e8 ac 1a 00 00 8d 74 24 04 8d bc 24 50 01 00 00 e8 [3] ff 8d 05 [2] 34 08 89 04 24 c7 44 24 04 01 00 00 00 e8 [3] ff 8b 44 24 08 89 84 24 40 01 00 00 8d 0d [2] 34 08 89 0c 24 c7 44 24 04 01 00 00 00 e8 [3] ff 8b 44 24 08 89 84 24 3c 01 00 00 8d 0d [2] 34 08 89 0c 24 c7 44 24 04 00 00 00 00 e8 [3] ff 8b 44 24 08 89 84 24 38 01 00 00 8d 0d [2] 34 08 89 0c 24 c7 44 24 04 01 00 00 00 e8 [3] ff 8b 44 24 08 89 84 24 34 01 00 00 8d 0d [2] 34 08 89 0c 24 c7 44 24 04 00 }
        $s4 = { 81 ec 80 01 00 00 8d 05 [2] 37 08 89 04 24 e8 [3] ff 8b 44 24 04 89 44 24 78 8d 0d [2] 37 08 89 0c 24 e8 [3] ff 8b 44 24 04 89 84 24 84 00 00 00 8d 0d [2] 37 08 89 0c 24 e8 [3] ff 8b 44 24 04 8b 8c 24 90 01 00 00 8b 51 08 85 d2 0f 85 17 14 00 00 31 d2 89 44 24 }
   condition:
       uint32(0) == 0x464C457F and filesize > 300KB and all of ($s*)
}
