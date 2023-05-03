rule RAN_Blacksuit_May_2023_1 : ransomware blacksuit esxi
{
    meta:
        description = "Detect the ESXI variant of Blacksuit ransomware"
        author = "Arkbird_SOLG"
        date = "2023-05-03"
        reference1 = "https://twitter.com/malwrhunterteam/status/1653743100605394947"
        reference2 = "https://twitter.com/Unit42_Intel/status/1653760405792014336"
        hash1 = "1c849adcccad4643303297fb66bfe81c5536be39a87601d67664af1d14e02b9e"
        // ref royal ransomware group ? 
        //hash2 = "09a79e5e20fa4f5aae610c8ce3fe954029a91972b56c6576035ff7e0ec4c1d14"
        //hash3 = "06abc46d5dbd012b170c97d142c6b679183159197e9d3f6a76ba5e5abf999725"
        //hash4 = "b64acb7dcc968b9a3a4909e3fddc2e116408c50079bba7678e85fee82995b0f4"
        //hash5 = "b57e5f0c857e807a03770feb4d3aa254d2c4c8c8d9e08687796be30e2093286c"
        tlp = "Clear"
        adversary = "-"
    strings:
        $s1 = { 48 8d 4c 24 0c 41 b8 04 00 00 00 ba 01 00 00 00 be 06 00 00 00 89 df e8 [3] ff 85 c0 0f 85 01 01 00 00 4c 89 e7 e8 59 c3 ff ff 4c 89 e7 89 c5 e8 2f c3 ff ff 89 df 89 ea 48 89 c6 e8 [3] ff 89 c7 b8 01 00 00 00 }
        $s2 = { 48 8b 7f 28 e8 [2] f4 ff 48 8d 35 [2] 0b 00 48 8d 3d [2] 0b 00 c7 05 [3] 00 01 00 00 00 e8 [3] ff 48 85 c0 48 89 05 [3] 00 0f 84 ed 00 00 00 48 8d 35 [2] 0b 00 48 8d 3d [2] 0b 00 e8 [3] ff 48 85 c0 48 89 05 [3] 00 0f 84 e2 00 00 00 48 8b 3d [3] 00 e8 [3] ff 48 8d 35 [3] 00 89 c7 e8 [3] ff 89 c2 b8 01 00 }
        $s3 = { 48 8d 85 30 fa ff ff ba 00 04 00 00 be 00 00 00 00 48 89 c7 e8 [2] ff ff 48 8d 95 30 fe ff ff 48 8d 85 30 fa ff ff be [2] 58 00 48 89 c7 b8 00 00 00 00 e8 [2] ff ff e8 [2] ff ff 89 45 c8 83 7d c8 00 75 }
        $s4 = { 89 ce 48 83 ec 18 48 89 d3 e8 20 ff ff ff 48 85 c0 49 89 c4 74 2a 48 8d 35 [3] 00 48 89 ea 48 89 c7 e8 26 fd ff ff 85 c0 74 32 48 85 db 74 0f 48 89 de 4c 89 e7 e8 92 fe ff ff 85 c0 74 1e 4c 89 e0 48 8b 1c 24 48 8b 6c 24 08 4c 8b 64 24 10 }
    condition:
       uint32(0) == 0x464C457F and filesize > 300KB and all of ($s*) 
}
