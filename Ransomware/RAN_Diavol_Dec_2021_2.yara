rule RAN_Diavol_Dec_2021_2
{
    meta:
        description = "Detect the Diavol ransomware (x64 version)"
        author = "Arkbird_SOLG"
        date = "2021-12-20"
        reference = "Internal Research"
        hash1 = "ee13d59ae3601c948bd10560188447e6faaeef5336dcd605b52ee558ff2a8588"
        hash2 = "b3da793a00eebaf8987fe2b759369e3d7ff02d91111c219c707bcb9709357637"
        tlp = "Clear"
        adversary = "Diavol"
    strings:
        $s1 = { 48 83 ec 68 48 8b 05 c9 4e 01 00 48 33 c4 48 89 44 24 48 48 83 3d 71 62 01 00 ff 0f 84 c0 00 00 00 48 8d 4c 24 38 48 89 5c 24 60 ff 15 5b ff 00 00 0f b7 54 24 46 0f b7 44 24 44 44 0f b7 4c 24 42 44 0f b7 44 24 40 48 8b 0d 66 be 01 00 89 54 24 28 48 8d 15 ab 2b 01 00 89 44 24 20 ff 15 59 01 01 00 4c 8b 44 24 70 b9 f6 27 00 00 48 63 d8 4c 8d 4c 24 78 2b cb 48 63 d1 48 8b 0d 33 be 01 00 48 8d 0c 59 e8 26 0d 00 00 44 8b d8 83 f8 ff 74 4a 48 8b 15 1b be 01 00 33 c0 48 83 c9 ff 48 89 7c 24 58 48 8b fa 45 8d 04 1b 66 f2 af 8b 0d 7c 2b 01 00 4c 8d 4c 24 30 89 4f fe 48 8b 0d c9 61 01 00 47 8d 44 00 02 89 44 24 30 48 89 44 24 20 ff 15 7d fe 00 00 48 8b }
        $s2 = { 48 8d 94 24 40 02 00 00 48 8d 0d 55 2c 01 00 41 b8 04 01 00 00 ff 15 21 00 01 00 4c 8d 4c 24 30 4c 8d 84 24 40 02 00 00 33 d2 33 c9 89 5c 24 28 48 89 5c 24 20 ff 15 c9 01 01 00 48 8b 8c 24 50 04 00 00 48 33 cc e8 31 01 00 00 48 81 c4 60 04 00 00 }
        $s3 = { 48 83 ec 20 48 8b 05 23 e5 00 00 48 83 64 24 30 00 48 bf 32 a2 df 2d 99 2b 00 00 48 3b c7 74 0c 48 f7 d0 48 89 05 0c e5 00 00 eb 76 48 8d 4c 24 30 ff 15 17 96 00 00 48 8b 5c 24 30 ff 15 74 97 00 00 44 8b d8 49 33 db ff 15 b8 96 00 00 44 8b d8 49 33 db ff 15 54 97 00 00 48 8d 4c 24 38 44 8b d8 49 33 db ff 15 3b 97 00 00 4c 8b 5c 24 38 4c 33 db 48 b8 ff ff ff ff ff ff 00 00 4c 23 d8 48 b8 33 a2 df 2d 99 2b 00 00 4c 3b df 4c 0f 44 d8 4c 89 1d 96 e4 00 00 49 }
        $s4 = { 48 81 ec a0 00 00 00 48 8b 05 9f 59 01 00 48 33 c4 48 89 84 24 90 00 00 00 49 63 f0 48 8b ea 4c 8b e1 ff 15 65 0c 01 00 33 c9 48 8b d8 ff 15 82 09 01 00 48 8b d3 48 8b c8 48 8b f8 ff 15 6b 09 01 00 41 bd 20 00 00 00 4c 8d 44 24 40 41 8b d5 48 8b cb ff 15 64 09 01 00 8b 44 24 44 44 8b 4c 24 48 89 44 24 64 45 33 db 4c 8d 35 05 c9 01 00 41 0f af c1 c1 e0 02 44 89 5c 24 30 45 33 c0 89 44 24 74 48 8d 44 24 60 48 8b d3 48 89 44 24 28 49 8b 04 f6 48 8b cf c7 44 24 60 28 00 00 00 48 c7 44 24 6c 01 00 20 00 44 89 4c 24 68 48 89 44 24 20 4c 89 9c 24 84 00 00 00 44 89 9c 24 80 00 00 00 4c 8b ee ff 15 da 08 01 00 48 8b cf ff 15 f1 08 01 00 4c 8d 05 22 35 01 00 48 8b d5 49 8b cc ff 15 ae 09 01 00 49 8b cc 48 8b d0 48 8b d8 ff 15 97 09 01 00 48 8b c8 ff 15 26 09 01 00 48 8b d3 49 8b cc 48 8b f8 ff 15 cf 08 01 00 8b 1f 8b f0 48 83 c7 04 83 ee 04 74 2c 48 8b cf ff 15 e9 08 01 00 48 8d 57 20 48 8b c8 ff 15 cc 08 01 00 4b 8b 0c ee 8b d3 48 83 c7 40 83 c3 08 83 c6 c0 48 89 04 0a 75 d4 48 8b 8c 24 90 00 00 00 48 33 cc e8 8e 0a 00 00 48 81 c4 }
    condition:
      uint16(0) == 0x5A4D and filesize > 90KB and all of ($s*) 
}