rule APT_Loader_SharpPanda_Jul_2022_1 : loader sharppanda
{
   meta:
        description = "Detect the loader used by SharpPanda"
        author = "Arkbird_SOLG"
        reference = "https://twitter.com/nao_sec/status/1547445181578121216"
        date = "2022-07-14"
        hash1 = "390e6820b2cc173cfd07bcebd67197c595f4705cda7489f4bc44c933ddcf8de6"
        hash2 = "1e18314390302cd7181b710a03a456de821ad85334acfb55f535d311dd6b3d65"
        hash3 = "c4500ad141c595d83f8dba52fa7a1456959fb0bc2ee6b0d0f687336f51e1c14e"
        hash4 = "065d399f6e84560e9c82831f9f2a2a43a7d853a27e922cc81d3bc5fcd1adfc56"
        tlp = "White"
        adversary = "SharpPanda"
   strings:
        $s1 = { b8 [3] 10 e8 [2] 01 00 6a 07 33 db 33 c0 59 89 5d dc 89 4d e0 66 89 45 cc 89 5d fc 8d 7d e4 ab ab ab 89 5d e4 89 5d e8 89 5d ec 33 c0 89 5d c4 89 4d c8 66 89 45 b4 6a 01 c6 45 fc 02 e8 [2] 00 00 8b f0 59 89 75 ?? e8 [2] ff ff 6a 01 56 0f b6 f8 e8 [2] 00 00 59 59 85 ff 75 }
        $s2 = { 8b ec 83 e4 f8 81 ec 34 04 00 00 a1 04 ?? 02 10 33 c4 89 84 24 30 04 00 00 8b 45 08 83 24 24 00 83 64 24 04 00 89 44 24 10 8b 45 0c 53 56 57 89 44 24 18 8d 7c 24 28 33 c0 8b f1 ab 89 74 24 14 83 3e 00 ab ab ab 8b 3d 48 [2] 10 74 0a be dd 10 00 00 e9 3f 01 00 00 8d 44 24 28 50 ff 15 [3] 10 33 c9 41 89 4c }
        $s3 = { 74 09 ff 75 e0 ff 15 [3] 10 ff 75 e4 8b ce e8 [2] ff ff 8d 4d e4 e8 [2] ff ff 8b c6 e8 [2] 01 }
        $s4 = { 68 5c 03 00 00 b8 [2] 01 10 e8 [2] 01 00 89 95 ac fc ff ff 89 4d ec 33 f6 c7 45 d4 07 00 00 00 33 c0 89 75 d0 66 89 45 c0 6a 44 8d 85 7c ff ff ff 89 75 fc 56 50 e8 [2] 00 00 33 c0 8d bd 9c fc ff ff ab 8d 4d e0 83 c4 04 ab ab ab 33 c0 8d 7d e0 ab ab ab e8 f1 01 00 00 68 cc 02 00 00 8d 85 b0 fc ff ff c6 45 fc 01 56 50 8b fe 8b de e8 [2] 00 00 83 c4 0c 56 6a 29 ff 75 e0 56 ff 15 [3] 10 ff 75 e0 8d 4d c0 e8 12 02 00 00 68 [2] 02 10 8d 4d c0 e8 aa 02 00 00 83 7d d4 08 8d 8d 9c fc ff ff 51 8d 8d 7c ff ff ff 51 56 56 6a 04 56 56 56 8d 45 c0 0f 43 45 c0 56 50 ff 15 [3] 10 85 c0 0f 84 05 01 00 00 56 ff b5 ac fc ff ff 56 6a 40 56 6a ff ff 15 [3] 10 8b f8 85 ff 0f 84 e8 00 00 00 ff b5 ac fc ff ff 56 56 6a 02 57 ff 15 [3] 10 8b d8 85 db 0f 84 cd 00 00 00 ff b5 ac fc ff ff ff 75 ec 53 e8 [2] 00 00 8b 85 9c fc ff ff 83 c4 0c 89 85 98 fc ff ff 68 [2] 02 10 68 [2] 02 10 ff 15 [3] 10 50 ff 15 [3] 10 89 b5 ac fc ff }
   condition:
       uint16(0) == 0x5A4D and filesize > 80KB and all of ($s*)
}
