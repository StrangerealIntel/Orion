rule RAN_ELF_Royal_Feb_2022_1 : royal ransomware x64 elf 
{
   meta:
        description = "Detect ELF version of Royal ransomware"
        author = "Arkbird_SOLG"
        reference = "https://twitter.com/BushidoToken/status/1621087221905514496"
        date = "2022-02-04"
        hash1 = "06abc46d5dbd012b170c97d142c6b679183159197e9d3f6a76ba5e5abf999725"
        hash2 = "b64acb7dcc968b9a3a4909e3fddc2e116408c50079bba7678e85fee82995b0f4"
        hash3 = "b57e5f0c857e807a03770feb4d3aa254d2c4c8c8d9e08687796be30e2093286c"
        tlp = "clear"
        adversary = "RAAS"
   strings:
        $s1 = { 48 83 ec 60 48 89 7d 98 bf 20 0c 82 00 e8 06 f6 ff ff 48 89 45 d8 48 83 7d d8 00 75 0a b8 00 00 00 00 e9 5c 02 00 00 bf 00 a0 0f 00 e8 cf d5 ff ff 48 89 45 e0 48 83 7d e0 00 75 0b b8 00 00 00 00 e9 3d 02 00 00 90 bf 60 36 82 00 e8 2f dd ff ff bf 40 36 82 00 e8 43 07 00 00 48 85 c0 0f 94 c0 84 c0 74 1c be 60 36 82 00 bf a0 36 82 00 e8 6c db ff ff bf 60 36 82 00 e8 e2 dd ff ff }
        $s2 = { ba 00 01 00 00 be 00 00 00 00 48 89 c7 e8 17 e8 ff ff 8b 45 ec 48 63 d0 48 8b 4d d8 48 8d 85 30 fe ff ff 48 89 ce 48 89 c7 e8 8b ed ff ff 48 8d 85 30 fa ff ff ba 00 04 00 00 be 00 00 00 00 48 89 c7 e8 e2 e7 ff ff 48 8d 95 30 fe ff ff 48 8d 85 30 fa ff ff be f0 0d 58 00 48 89 c7 b8 00 00 00 00 e8 f2 eb ff ff e8 cd ef ff ff 89 45 c8 83 7d c8 00 75 33 48 8d 85 30 fa ff ff 41 b8 00 00 00 00 48 89 c1 ba dd 0d 58 00 be e0 0d 58 00 bf e0 0d 58 00 b8 00 00 00 00 e8 eb e9 ff ff bf }
        $s3 = { 48 81 ec c8 05 00 00 e8 ae f1 ff ff 89 45 c8 83 7d c8 00 75 2e 41 b8 00 00 00 00 b9 bf 0d 58 00 ba dd 0d 58 00 be e0 0d 58 00 bf e0 0d 58 00 b8 00 00 00 00 e8 d1 eb ff ff bf 00 }
        $s4 = { 48 8b 45 e8 48 83 c0 13 be 4e 0e 58 00 48 89 c7 e8 db e9 ff ff 48 85 c0 0f 85 28 01 00 00 48 8b 45 e8 48 83 c0 13 be 53 0e 58 00 48 89 c7 e8 bd e9 ff ff 48 85 c0 0f 85 0d 01 00 00 48 8b 45 e8 48 83 c0 13 be 5e 0e 58 00 48 89 c7 e8 4f eb ff ff }
    condition:
        uint32(0) == 0x464C457F and filesize > 30KB and all of ($s*) 
}
