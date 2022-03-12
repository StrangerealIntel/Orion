rule RAN_Nokoyawa_Mar_2022_1 : nokoyawa ransomware
{
   meta:
      description = "Detect nokoyawa ransomware"
      author = "Arkbird_SOLG"
      reference = "https://www.trendmicro.com/en_us/research/22/c/nokoyawa-ransomware-possibly-related-to-hive-.html"
      date = "2022-03-12"
      hash1 = "e097cde0f76df948f039584045acfa6bd7ef863141560815d12c3c6e6452dce4"
      hash2 = "fefd1117c2f0ab88d8090bc3bdcb8213daf8065f12de1ee6a6c641e888a27eab"
      adversary = "-"
   strings:
      $s1 = { b9 f5 ff ff ff ff 15 1a 6e 00 00 48 c7 44 24 20 00 00 00 00 45 33 c9 8b 4c 24 38 44 8b c1 48 8d 15 18 71 00 00 48 8b c8 ff 15 ff 6d 00 00 48 8d 0d 58 71 00 00 e8 a3 62 00 00 89 44 24 3c b9 f5 ff ff ff ff 15 dc 6d 00 00 48 c7 44 24 20 00 00 00 00 45 33 c9 8b 4c 24 3c 44 8b c1 48 8d 15 8a 71 00 00 48 8b c8 ff 15 c1 6d 00 00 48 8d 0d d2 71 00 00 e8 65 62 00 00 89 44 24 40 b9 f5 ff ff ff ff 15 9e 6d 00 00 48 c7 44 24 20 00 00 00 00 45 33 c9 8b 4c 24 40 44 8b c1 48 8d 15 e4 71 00 00 48 8b c8 ff 15 83 6d 00 00 48 8d 0d 2c 72 00 00 e8 27 62 00 00 89 44 24 44 b9 f5 ff ff ff ff 15 60 6d 00 00 48 c7 44 24 20 00 00 00 00 45 33 c9 8b 4c 24 44 44 8b c1 48 8d 15 4e 72 00 00 48 8b c8 ff 15 45 6d 00 00 e9 8a }
      $s2 = { 48 6b c0 00 0f b7 4c 24 20 66 89 4c 04 28 b8 02 00 00 00 48 6b c0 01 b9 3a 00 00 00 66 89 4c 04 28 b8 02 00 00 00 48 6b c0 02 b9 5c 00 00 00 66 89 4c 04 28 b8 02 00 00 00 48 6b c0 03 33 c9 66 89 4c 04 28 48 8d 4c 24 28 ff 15 a9 5c 00 00 89 44 24 24 83 7c }
      $s3 = { 48 81 ec 78 02 00 00 c7 44 24 40 00 40 00 00 c7 44 24 4c ff ff ff ff 48 8d 44 24 50 48 89 44 24 20 4c 8b 8c 24 80 02 00 00 45 33 c0 33 d2 b9 02 00 00 00 ff 15 ca 5e 00 00 89 44 24 48 83 7c 24 48 00 74 07 33 c0 e9 40 01 00 00 8b 44 24 40 8b d0 b9 40 00 00 00 ff 15 57 5e 00 00 48 89 44 24 38 }
      $s4 = { 48 83 ec 28 45 33 c9 45 33 c0 33 d2 48 c7 c1 ff ff ff ff ff 15 47 69 00 00 48 }
      $s5 = { 48 48 8d 0d 45 7e 00 00 ff 15 af 6a 00 00 8b 05 59 7e 00 00 89 44 24 34 e8 50 01 00 00 48 89 05 19 7e 00 00 8b 44 24 34 d1 e0 48 98 48 c1 e0 03 48 8b c8 e8 85 5c 00 00 }
   condition:
      uint16(0) == 0x5A4D and filesize > 15KB and all of ($s*)
}
