rule APT_Earth_Berberoka_Tifa_Oct_2022_1 : diceyf tifa downloader
{
   meta:
      description = "Detects the tifa version of the downloader used by the Earth Berberoka"
      author = "Arkbird_SOLG"
      reference = "https://securelist.com/diceyf-deploys-gameplayerframework-in-online-casino-development-studio/107723/"
      date = "2022-10-20"
      hash1 = "8aacb0fd6ea3143d0e7a6b56f7b90c3be760bcc8abbbb29c4334b50f06e822f"
      level = "experimental"
      tlp = "clear"
      adversary = "Earth Berberoka"
   strings:
      $s1 = { 7b 00 7b 00 22 00 43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 4e 00 61 00 6d 00 65 00 22 00 3a 00 22 00 7b 00 30 00 7d 00 22 00 2c 00 22 00 47 00 75 00 69 00 64 00 22 00 3a 00 22 00 7b 00 31 00 7d }
      $s2 = { 7b 00 30 00 3a 00 58 00 38 00 7d 00 2d 00 7b 00 31 00 3a 00 58 00 34 00 7d 00 2d 00 7b 00 32 00 3a 00 58 00 34 00 7d }
      $s3 = { 20 3c 21 2d 2d 20 57 69 6e 64 6f 77 73 20 38 2e 31 20 2d 2d 3e 0d 0a 20 20 20 20 20 20 3c 21 2d 2d 3c 73 75 70 70 6f 72 74 65 64 4f 53 20 49 64 3d 22 7b }
      $s4 = { 73 1b 00 00 06 0a 06 72 01 00 00 70 20 37 33 00 00 6f 13 00 00 06 2c 3a 06 02 72 25 00 00 70 6f 15 00 00 06 2c 2c 16 0b 2b 1d 06 6f 16 00 00 06 0c 08 2c 0f 06 6f 1a 00 00 06 08 03 28 0a 00 00 06 de 1e 07 17 58 0b 07 1f 1e 32 de 06 6f 1a 00 00 06 20 88 13 00 00 28 13 00 00 0a }
      $s5 = { 28 06 00 00 06 2d 0b 72 27 00 00 70 28 05 00 00 06 2a 72 27 00 00 70 72 25 00 00 70 28 01 00 00 06 2a 02 16 9a 16 6f 2a }
   condition:
      uint16(0) == 0x5a4d and filesize > 10KB and all of ($s*)
}
