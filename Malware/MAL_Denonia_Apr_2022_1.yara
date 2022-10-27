rule MAL_Denonia_Apr_2022_1 : denonia aws
{
   meta:
        description = "Detect the Denonia backdoor"
        author = "Arkbird_SOLG"
        reference = "https://www.cadosecurity.com/cado-discovers-denonia-the-first-malware-specifically-targeting-lambda/"
        date = "2022-04-09"
        hash1 = "739fe13697bc55870ceb35003c4ee01a335f9c1f6549acb6472c5c3078417eed"
        hash2 = "a31ae5b7968056d8d99b1b720a66a9a1aeee3637b97050d95d96ef3a265cbbca"
        tlp = "Clear"
        adversary = "-"
   strings:
        $s1 = { 48 8b 43 28 4c 89 ee 48 89 df 48 89 05 [3] 00 e8 1a f3 ff ff 4c 89 e2 49 89 c6 48 8b 05 [3] 00 48 85 c0 74 1a 48 8b 0b eb 10 0f 1f 00 48 8d 50 28 48 8b 40 28 48 85 c0 74 05 48 39 08 73 ee 48 89 43 28 48 89 1a 4d 85 f6 74 a2 e9 06 ff ff ff 45 31 f6 e9 a1 fe ff ff 49 63 46 04 49 8d 7e 04 48 29 c7 e8 35 e2 ff ff 0f }
        $s2 = { 48 8d 75 10 4c 8d b5 d0 fe ff ff 41 55 4c 8d ad e0 fd ff ff 41 54 49 89 fc 4c 89 ef 53 52 50 48 81 ec f8 01 00 00 48 8b 55 08 e8 e9 f3 ff ff f3 0f 6f 85 e0 fd ff ff 4c 89 f6 f3 0f 6f 8d f0 fd ff ff f3 0f 6f 95 00 fe ff ff f3 0f 6f 9d 10 fe ff ff 48 8d 95 d8 fd ff ff 4c 89 e7 f3 0f 6f a5 20 fe ff ff f3 0f 6f ad 30 fe ff ff 0f 11 85 d0 fe ff ff f3 0f 6f b5 40 fe ff ff f3 0f 6f bd 50 fe ff ff 0f 11 8d e0 fe ff ff f3 0f 6f 85 60 fe ff ff f3 0f 6f 8d 70 fe ff ff 0f 11 95 f0 fe ff ff 0f 11 9d 00 ff ff ff }
        $s3 = { 48 89 d3 48 81 ec 98 01 00 00 f3 48 ab 4c 8d 6c 24 10 48 89 ef 4c 89 ee 48 8b 84 24 b8 01 00 00 48 89 85 98 00 00 00 48 b8 00 00 00 00 00 00 00 40 48 89 85 c0 00 00 00 e8 30 fb ff ff 85 c0 0f 85 [3] ff 48 8d 35 01 e3 ff ff 48 8d 3d [3] 00 e8 6f 3a 01 00 85 c0 74 09 80 3d [3] 00 00 74 78 80 3d [3] 00 08 0f 85 [3] ff 4c 89 64 24 08 f6 85 c7 00 00 00 40 74 07 c6 85 df 00 00 00 00 }
        $s4 = { 48 85 d2 74 38 41 80 3c 03 08 0f 85 [3] ff 48 89 74 24 08 4c 39 d2 73 0d 48 8d 4a 08 49 39 ca 0f 82 [3] ff 48 8d 7c 24 10 48 39 fa 73 09 4c 39 d2 0f 87 [3] ff 48 89 32 48 83 c0 01 48 83 f8 11 0f 84 cd 00 00 00 41 80 bc 01 d8 00 00 00 00 49 8b 14 c1 49 8b 34 c0 0f 85 [3] ff 41 80 bc 00 d8 00 00 00 00 75 93 48 }
        $s5 = { 4c 89 c2 4c 89 e6 e8 da 54 08 00 85 db b8 00 08 00 00 48 8b 7d 08 0f 4e d8 48 63 f3 e8 7e 69 ef ff 85 c0 0f 84 ae 00 00 00 45 85 f6 0f 8f 7d 00 00 00 45 85 ff 7e 36 41 81 ff a3 00 00 00 74 2d e8 ca de ef ff 48 89 45 18 48 85 c0 0f 84 85 00 00 00 44 89 ff e8 b5 1e f5 ff 48 8b 7d 18 31 c9 ba 05 00 00 00 48 }
   condition:
       uint32(0) == 0x464C457F and filesize > 300KB and all of ($s*)
}
