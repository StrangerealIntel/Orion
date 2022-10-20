rule APT_Earth_Berberoka_Yuma_Oct_2022_1 : diceyf yuma downloader
{
   meta:
      description = "Detects the yuma version of the downloader used by the Earth Berberoka"
      author = "Arkbird_SOLG"
      reference = "https://securelist.com/diceyf-deploys-gameplayerframework-in-online-casino-development-studio/107723/"
      date = "2022-10-20"
      hash1 = "0c808ffffa946931b0e6c90346690392e01aee9b610d83385af2290f8df71001"
      hash2 = "18bc154c0fe1399f6e1fce92c1ec3debd3a59fde09d9c33398ae097eee311f67"
      hash3 = "9ba967dd0fc99efb64d5074d6491834f5b514340446734a07e46a1cf846d3de5"
      tlp = "clear"
      adversary = "Earth Berberoka"
   strings:
      $s1 = { 00 00 0a 26 2a 06 7b ?? 00 00 04 72 [2] 00 70 6f ?? 00 00 0a [4-7] 00 00 0a 6f ?? 00 00 0a 0d 06 7b ?? 00 00 04 72 [2] 00 70 6f ?? 00 00 0a 26 00 [2] ?? 00 00 }
      $s2 = { 28 ?? 00 00 0a 6f ?? 00 00 0a 25 2d 04 26 14 2b 05 28 ?? 00 00 0a 0b 12 00 02 28 08 00 00 2b 7d ?? 00 00 04 06 7b ?? 00 00 04 6f ?? 00 00 0a 2d ?? 72 [2] 00 70 73 ?? 00 00 0a 25 16 28 ?? 00 00 0a 16 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 08 28 ?? 00 00 0a 2d 0b 08 28 ?? 00 00 06 28 ?? 00 00 0a }
      $s3 = { 10 00 45 25 00 00 00 00 00 00 c9 00 8d 05 29 0e 03 01 10 00 57 15 00 00 00 00 00 00 c9 00 92 05 2b 0e 03 01 10 00 c1 1d 00 00 00 00 00 00 c9 00 99 05 2d 0e 03 01 10 00 82 1b 00 00 00 00 00 00 c9 00 a0 05 2f 0e 03 01 10 }
      $s4 = { 23 7b 00 22 00 43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 4e 00 61 00 6d 00 65 00 22 00 3a 00 22 00 00 23 22 00 2c 00 22 00 52 00 65 00 71 00 75 00 65 00 73 00 74 00 4e 00 61 00 6d 00 65 00 22 00 3a 00 22 }
   condition:
      uint16(0) == 0x5a4d and filesize > 120KB and all of ($s*)
}
