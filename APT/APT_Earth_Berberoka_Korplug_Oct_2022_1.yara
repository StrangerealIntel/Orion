rule APT_Earth_Berberoka_Korplug_Oct_2022_1 : diceyf korplug
{
   meta:
      description = "Detects Korplug implant used by the Earth Berberoka"
      author = "Arkbird_SOLG"
      reference = "https://securelist.com/diceyf-deploys-gameplayerframework-in-online-casino-development-studio/107723/"
      date = "2022-10-20"
      hash1 = "5a9468a87997f2363995e264505105f6a235b66543bb28635fb74f78704e9111"
      hash2 = "9aff1e12a1b447ca8ab3076f684716a859c906f9b2d0e870d59d0f06fc548d0d"
      hash3 = "a2a0ce67c239385c1ec1d5d29ff91a7daf91cf2b4368dc91d84dbb598becdc5d"
      tlp = "clear"
      adversary = "Earth Berberoka"
   strings:
      $s1 = { 68 9c 78 42 00 52 ff d3 a1 ?? 75 43 00 83 c4 10 85 c0 75 31 68 ?? 85 42 00 ff 15 ?? 52 42 00 a3 ?? 75 43 00 85 c0 75 10 68 ?? 85 42 00 ff 15 44 53 42 00 a3 ?? 75 43 00 68 ?? 85 42 00 50 ff d7 a3 ?? 75 43 00 68 50 02 00 00 8d 8c 24 ec 04 00 00 6a 00 51 ff d0 83 c4 0c 8d 94 24 e8 04 00 00 52 8d 84 24 9c 00 00 00 50 ff 15 ?? 51 42 00 8b f0 83 fe ff 75 31 8b 94 24 90 00 00 00 8d 8c 24 98 02 00 00 51 52 ff 15 ?? 51 42 00 85 c0 0f 85 16 ff ff ff 8b 8c 24 90 00 00 00 51 ff 15 ?? 51 42 00 e9 c2 fd ff ff 68 d0 78 42 00 8d 84 24 9c 00 00 00 50 8d 8c 24 40 07 00 00 68 ec 78 42 00 51 ff d3 a1 ?? 75 43 00 83 c4 10 85 c0 }
      $s2 = { 8d 45 cc 68 ?? 69 43 00 50 e8 ?? cb 00 00 8d 8e 08 1a 00 00 83 c4 08 83 c6 04 89 7d f8 89 4d f4 89 75 fc eb 02 33 ff 8b 55 f8 8b 45 d8 52 50 68 10 73 42 00 53 ff 15 b0 53 42 00 83 c4 10 53 ff 15 ?? 52 42 00 8b 4d f4 51 8b f0 c7 45 f0 00 00 00 00 ff 15 ?? 52 42 00 83 fe }
      $s3 = { 8b 45 08 8b 48 04 68 10 f0 00 00 57 89 4e 18 ff d3 68 44 72 42 00 8b d8 89 7c 24 24 89 7c 24 2c 89 7c 24 28 89 7c 24 20 ff 15 ?? 52 42 00 8b f8 03 ff 68 44 72 42 00 8d 44 24 20 e8 [2] ff ff 8b 44 24 1c 99 2b c2 8b 54 24 28 d1 f8 66 83 7c 42 fe 5c 74 10 6a 02 68 ?? 6f 42 00 8d 44 24 24 e8 [2] ff ff 68 58 72 42 00 ff 15 ?? 52 42 00 03 c0 50 68 58 72 42 00 }
      $s4 = { 8b 45 08 53 8b 1d ac 53 42 00 56 57 8b 7d 0c 50 8d 4d ac 33 f6 68 ?? 82 42 00 51 89 75 f8 c7 45 cc ?? 82 42 00 89 75 d0 ff d3 a1 ?? 77 43 00 83 c4 0c 3b c6 75 2a a1 ?? 76 43 00 3b c6 75 10 68 ?? 80 42 00 ff 15 44 53 42 00 a3 ?? 76 43 00 68 ?? 85 42 00 50 ff }
   condition:
      uint16(0) == 0x5a4d and filesize > 80KB and all of ($s*)
}
