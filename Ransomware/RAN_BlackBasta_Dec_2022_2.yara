rule RAN_BlackBasta_Dec_2022_2 : blackbasta ransomware
{
   meta:
        description = "Detect the BlackBasta ransomware (EXE v2)"
        author = "Arkbird_SOLG"
        reference = "https://www.zscaler.com/blogs/security-research/back-black-basta"
        date = "2022-12-01"
        hash1 = "350ba7fca67721c74385faff083914ecdd66ef107a765dfb7ac08b38d5c9c0bd"
        hash2 = "c4c8be0c939e4c24e11bad90549e3951b7969e78056d819425ca53e87af8d8ed"
        hash3 = "e28188e516db1bda9015c30de59a2e91996b67c2e2b44989a6b0f562577fd757"
        tlp = "clear"
        adversary = "RAAS"
   strings:
        $s1 = { 80 f9 40 73 15 80 f9 20 73 06 0f a5 c2 d3 e0 c3 8b d0 33 c0 80 e1 1f d3 e2 c3 33 c0 33 d2 c3 cc 80 f9 40 73 16 80 f9 20 73 06 0f ad d0 d3 fa c3 8b c2 c1 fa 1f 80 e1 1f d3 f8 c3 c1 fa 1f 8b }
        $s2 = { ( 41 00 a3 [2] 44 00 5d c3 cc 55 8b ec a1 [2] 41 00 a3 [2] 44 00 8b 0d [2] 41 00 89 0d ( 14 31 | 4c 19 ) | d0 d1 40 00 a3 c4 40 44 00 5d c3 cc 55 8b ec a1 b8 d0 40 00 a3 f8 43 44 00 8b 0d 9c d0 40 00 89 0d fc 43 ) 44 00 8b 15 }
        $s3 = { 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00 00 00 10 00 00 00 10 08 02 00 00 00 90 91 68 36 00 00 01 d7 49 44 41 54 78 9c a5 52 3d 4c 53 51 18 3d f7 dd db 27 85 56 c1 0a 83 d1 a4 29 21 86 c1 9f 4e 76 d2 68 88 31 b1 a3 0e }
    condition:
        uint16(0) == 0x5A4D and filesize > 200KB and all of ($s*) 
}
