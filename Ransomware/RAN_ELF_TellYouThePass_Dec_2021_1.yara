rule RAN_ELF_TellYouThePass_Dec_2021_1
{
    meta:
        description = "Detect the ELF version of TellYouThePass ransomware"
        author = "Arkbird_SOLG"
        date = "2021-12-21"
        reference = "Internal Research"
        hash1 = "5c8710638fad8eeac382b0323461892a3e1a8865da3625403769a4378622077e"
        tlp = "white"
        adversary = "TellYouThePass"
        level="Experimental"
    strings:
        $s1 = { 48 83 ec 38 48 89 6c 24 30 48 8d 6c 24 30 48 89 44 24 40 48 89 5c 24 48 b9 19 00 00 00 48 8b 44 24 38 48 8d 1d f2 90 21 00 e8 4c fd ff ff 44 0f 11 7c 24 18 66 c7 44 24 28 00 00 48 8b 54 24 40 48 89 54 24 18 c6 44 24 28 01 48 8b 54 24 48 48 89 54 24 20 c6 44 24 29 01 48 8d 05 ba 05 20 00 48 8d 5c 24 18 e8 b0 a6 fd ff e8 ab 25 00 00 90 48 89 44 24 08 48 89 5c 24 10 e8 db 01 03 00 48 8b 44 24 08 48 8b 5c 24 }
        $s2 = { 48 89 8c 24 e0 00 00 00 48 89 74 24 78 48 8b 01 48 89 84 24 d8 00 00 00 48 8b 51 50 48 89 94 24 d0 00 00 00 e8 42 87 fe ff 48 8d 05 a9 fd 1f 00 bb 20 00 00 00 e8 51 90 fe ff 48 8b 44 24 78 e8 a7 8e fe ff 48 8d 05 40 71 1f 00 bb 04 00 00 00 e8 36 90 fe ff 48 8b 84 24 e0 00 00 00 e8 a9 8f fe ff 48 8d 05 63 7e 1f 00 bb 09 00 00 00 e8 18 90 fe ff 48 8b 84 24 c8 00 00 00 e8 8b 8f fe ff 48 8d 05 39 77 1f 00 bb 07 00 00 00 e8 fa 8f fe ff 48 8b 84 24 d8 00 00 00 e8 6d 8f fe ff 48 8d 05 2a 8c 1f 00 bb 0c 00 00 00 90 e8 db 8f fe }
        $s3 = { 6c 6f 63 61 6c 2e 6f 6e 69 6f 6e 2f 70 72 6f 63 2f 31 32 37 }
        $s4 = { 43 6c 69 65 6e 74 50 75 62 4b 65 79 0c 73 73 68 74 79 70 65 3a 22 }
        $s5 = { 0f 1f 80 00 00 00 00 48 89 6c 24 f0 48 8d 6c 24 f0 e8 83 5c ee ff 48 8b 6d 00 48 89 9c 24 c0 06 00 00 48 89 94 24 c8 06 00 00 48 8b 94 24 20 01 00 00 48 89 94 24 d0 06 00 00 4c 89 9c 24 d8 06 00 00 4c 89 8c 24 e0 06 00 00 4c 89 94 24 e8 06 00 00 48 8b 94 24 50 01 00 00 48 89 94 24 78 07 00 00 48 8b 94 24 a8 00 00 00 48 89 94 24 80 07 00 00 48 8b 94 24 b0 00 00 00 48 89 94 24 88 07 00 00 4c 89 a4 24 90 07 00 00 48 89 8c 24 98 07 00 00 4c 89 84 24 a0 07 00 00 48 8b 50 40 4c 8b 40 48 4c 8b 48 50 48 89 94 24 a8 07 00 00 4c 89 84 24 b0 07 00 00 4c 89 8c 24 b8 07 00 00 0f b6 54 24 2f 88 94 24 c0 07 00 00 0f b6 54 24 2e 88 94 24 c1 07 00 00 0f b6 90 88 00 00 00 88 94 24 c2 07 00 00 48 8b bc 24 00 0a 00 00 84 07 83 3d 52 46 2a 00 }
    condition:
      uint32(0) == 0x464C457F and filesize > 800KB and 4 of ($s*)     
}