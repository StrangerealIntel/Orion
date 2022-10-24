rule WIP_Unk_Ukr_Feb_2022_1 : wiper
{
   meta:
      description = "Detect wiper implant used during Ukrainian crisis"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/ESETresearch/status/1496581903205511181"
      date = "2022-02-24"
      hash1 = "0385eeab00e946a302b24a91dea4187c1210597b8e17cd9e2230450f5ece21da"
      hash2 = "1bc44eef75779e3ca1eefb8ff5a64807dbc942b1e4a2672d77b9f6928d292591"
      adversary = "-"
   strings:
      $s1 = { 8d 45 fc c7 45 fc 00 00 00 00 50 68 ?? 56 40 00 68 02 00 00 80 ff 15 4c 50 40 00 85 c0 75 24 6a 04 89 45 f4 8d 45 f4 50 6a 04 6a 00 68 ?? 57 40 00 ff 75 fc ff 15 54 50 40 00 ff 75 fc ff 15 50 50 40 00 6a 00 68 d0 51 40 00 8d 85 60 f9 ff ff 68 04 01 00 00 50 ff 15 ?? 51 40 00 83 c4 10 8d 8d 60 f9 ff ff 33 d2 6a 00 e8 91 ec ff }
      $s2 = { 8b ec 81 ec 60 02 00 00 53 56 57 51 68 a8 51 40 00 0f 57 c0 89 55 e4 8d 85 a4 fd ff ff c7 45 f0 00 00 00 00 68 04 01 00 00 33 f6 66 0f d6 45 dc 33 ff 89 75 f4 50 0f 11 45 bc 89 7d e8 0f 11 45 cc ff 15 ?? 51 40 00 83 c4 10 8d 45 b0 8d 55 bc 8d 8d a4 fd ff ff 50 e8 b3 fa ff ff 8b d8 83 fb ff 0f 84 ab 01 00 00 85 db 0f 84 d8 01 00 00 bf c0 24 00 00 57 6a 08 ff 15 60 50 40 00 50 ff 15 5c 50 40 00 6a 00 8b f0 8d 45 f4 50 57 56 6a 00 6a 00 68 50 00 07 00 53 ff 15 }
      $s3 = { 8d 54 24 0c b9 90 22 40 00 e8 [2] ff ff 8d 44 24 0c ba 20 29 40 00 50 68 d0 28 40 00 b9 a0 52 40 00 e8 ?? f6 ff ff 8d 44 24 14 ba 70 29 40 00 50 68 90 28 40 00 b9 a0 52 40 00 e8 ?? f6 ff ff 83 c4 10 8d 44 24 0c ba 01 00 00 00 b9 e0 52 40 00 50 e8 [2] 00 00 8b 7c 24 30 8d 44 24 24 8b 74 24 34 50 ff 15 78 50 40 00 8b 4c 24 28 8b 44 24 24 2b ce 33 f6 2b c7 69 7c 24 3c 60 ea 00 00 56 68 10 27 00 00 51 50 e8 ?? cf ff ff }
      $s4 = { 44 24 1c ba 01 00 00 00 50 b9 ?? 55 40 00 e8 ?? 0d 00 00 8b 7c 24 30 8d 44 24 10 8b 74 24 34 50 ff 15 78 50 40 00 8b 4c 24 14 8b 44 24 10 2b ce 33 f6 2b c7 69 7c 24 24 60 ea 00 00 56 68 10 27 00 00 51 50 e8 30 d1 ff ff 2b f8 1b }
   condition:
      uint16(0) == 0x5A4D and filesize > 30KB and all of ($s*)
}


