rule RAN__Hive_March_2022_1 : hive v5 x64
{
   meta:
        description = "Detect Rust version of Hive ransomware (x64 version)"
        author = "Arkbird_SOLG"
        reference = "https://twitter.com/rivitna2/status/1514552342519107584"
        date = "2022-03-26"
        //updated 2022-04-14
        hash1 = "4587e7d8e56a7694aa1881443312c1774da551459d3a48315acd0c694bcf87a"
        hash2 = "1841ca56006417e6220a857f66c8e6539502d5e9f539cf337b83a25c15d17a50"
        hash3 = "efdbfcb717b109b816e2d2f99c0d923803c70dd08fb9feb747eb90774e86116e"
        tlp = "white"
        adversary = "RAAS"
   strings:
        $s1 = { 48 83 ec 38 48 89 cf 48 8d 71 38 48 89 f1 e8 [2] 04 00 48 8b 05 [2] 05 00 48 c1 e0 01 48 85 c0 75 13 31 d2 8a 47 40 84 c0 75 16 48 89 f0 48 83 c4 38 5f 5e c3 e8 [3] 00 89 c2 80 f2 01 eb e3 4c 8d 44 24 28 49 89 30 41 88 50 08 48 8d 05 [3] 00 48 89 44 24 20 48 8d 0d [3] 00 4c 8d 0d [3] 00 ba 2b 00 00 00 }
        $s2 = { 48 8b 0d [3] 00 31 d2 e8 [3] 00 b0 01 48 81 c4 f8 06 00 00 5b 5d 5f 5e 41 5c 41 5d 41 5e 41 5f c3 4c 8d 05 [3] 00 31 c9 31 d2 e8 [3] 00 48 85 c0 74 a8 48 89 c7 31 c0 f0 48 0f b1 3d }
        $s3 = { 48 c7 44 24 38 00 00 00 00 c7 44 24 30 00 00 00 00 c7 44 24 28 00 10 00 00 c7 44 24 20 00 10 00 00 ?? 89 ?? 8b 94 24 ?? 00 00 00 [0-1] 8b ?? 24 [2-5] 89 ?? 41 b9 01 00 00 00 e8 [2] 00 00 [0-3] 48 83 }
        $s4 = { 48 8d 6c 24 40 48 89 45 00 48 89 55 08 66 c7 45 10 00 00 c7 45 18 01 00 00 00 ?? 8d ?? 24 [2-5] 89 ?? 48 89 ea e8 [3] 00 ?? 8b ?? 48 89 ?? 24 30 ?? 89 ?? 24 28 4c 89 64 24 20 48 89 f1 31 d2 4d 89 f0 41 b9 ff ff ff ff e8 }
   condition:
        uint16(0) == 0x5A4D and filesize > 60KB and all of ($s*) 
}
