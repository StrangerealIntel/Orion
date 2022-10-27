rule RAN_Koxic_Jan_2022_1
{
   meta:
      description = " Detected Koxic ransomware"
      author = "Arkbird_SOLG"
      reference = "https://id-ransomware.blogspot.com/2022/01/koxic-ransomware.html"
      date = "2022-01-30" 
      hash1 = "7a5e20e021dc29a07cad61f4d0bdb98e22749f13c3ace58220bfe978908bb7e9"
      hash2 = "95202fe13309a9b1651766298c833b21494a92f0b210fc6469d79d3fa444db81"
      tlp = "Clear"
      adversary = "-"
   strings:
      $s1 = { c7 45 9c [2] 45 00 c7 45 a0 [2] 45 00 c7 45 a4 [2] 45 00 c7 45 a8 [2] 45 00 c7 45 ac [2] 45 00 c7 45 b0 [2] 45 00 c7 45 b4 [2] 45 00 c7 45 b8 [2] 45 00 c7 45 bc [2] 45 00 c7 45 c0 [2] 45 00 c7 45 c4 [2] 45 00 c7 45 c8 [2] 45 00 c7 45 cc [2] 45 00 c7 45 d0 [2] 45 00 c7 45 d4 [2] 45 00 c7 45 d8 [2] 45 00 c7 45 dc [2] 45 00 c7 45 e0 [2] 45 00 c7 45 e4 [2] 45 00 c7 45 f8 00 00 00 00 eb 09 8b 4d f8 83 c1 01 89 4d f8 83 7d f8 13 0f 83 b7 00 00 00 6a 44 6a 00 8d 95 48 ff ff ff 52 e8 [2] 01 00 83 c4 0c c7 85 48 ff ff ff 44 00 00 00 6a 10 6a 00 8d 45 e8 50 e8 [2] 01 00 83 c4 0c 8b 4d f8 8b 54 8d 9c 52 8d 85 f0 fc ff ff 50 ff 15 70 f0 42 00 68 [2] 46 00 8d 8d f0 fc ff ff 51 ff 15 54 f0 42 00 68 [2] 45 00 8d 95 f0 fc ff ff 52 ff 15 54 f0 42 00 8d 45 e8 50 8d 8d 48 ff ff ff 51 6a 00 6a 00 68 00 00 00 08 6a 00 6a 00 6a 00 8d 95 f0 fc ff ff 52 6a 00 ff 15 6c f0 42 00 89 45 98 6a ff 8b 45 e8 50 ff 15 40 f0 42 00 8b 4d e8 51 ff 15 58 f0 42 00 8b 55 ec 52 }
      $s2 = { 68 [3] 00 68 01 00 00 80 6a 03 8b ?? f0 ?? 6a 00 e8 ?? 15 00 00 83 c4 18 85 c0 }
      $s3 = { 56 8b 35 ?? f0 42 00 8d 44 24 0c 57 68 20 00 00 f0 6a 01 68 94 ?? 45 00 6a 00 50 c7 44 24 24 00 00 00 00 ff d6 8b 6c 24 20 85 c0 75 19 68 28 00 00 f0 6a 01 68 c0 ?? 45 00 6a 00 8d 44 24 20 50 ff d6 85 c0 74 31 53 55 ff 74 24 18 ff 15 ?? f0 42 00 6a 00 ff 74 24 14 83 f8 01 75 14 ff 15 ?? f0 42 00 85 ed 74 10 5f 5e 8b c5 5d 5b 83 c4 08 c3 ff 15 ?? f0 42 00 33 ff 33 f6 8b }
      $s4 = { 6a 00 6a 00 6a 00 ff 15 a8 f0 42 00 a3 [2] c6 00 6a 00 8b 0d [2] c6 00 51 ff 15 40 f0 42 00 85 c0 75 0d 8b 15 [2] c6 00 52 ff 15 ac f0 42 00 6a 00 6a 00 6a 00 ff 15 a8 f0 42 00 a3 [2] c6 00 6a 00 a1 [2] c6 00 50 ff 15 40 f0 42 00 85 c0 75 0d 8b 0d [2] c6 00 51 ff 15 ac f0 42 00 8b 55 e8 89 55 98 8b 45 f4 89 45 9c 8b 4d f8 89 4d a0 6a 00 6a 00 8d 55 98 52 68 d0 ?? 40 00 6a 00 6a 00 ff 15 bc f0 42 00 89 45 f0 8b 45 f8 89 45 b4 8b 4d f0 89 4d b8 c7 45 fc 00 00 00 }
   condition:
      uint16(0) == 0x5a4d and filesize > 100KB and all of ($s*)
}
