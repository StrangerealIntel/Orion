rule RAN_Maui_Jul_2022_1 : ransomware maui
{
   meta:
      description = "Detect Maui ransomware"
      author = "Arkbird_SOLG"
      reference1 = "https://stairwell.com/wp-content/uploads/2022/07/Stairwell-Threat-Report-Maui-Ransomware.pdf"
      date = "2022-07-07"
      hash1 = "5b7ecf7e9d0715f1122baf4ce745c5fcd769dee48150616753fec4d6da16e99e"
      hash2 = "45d8ac1ac692d6bb0fe776620371fca02b60cac8db23c4cc7ab5df262da42b78"
      hash3 = "830207029d83fd46a4a89cd623103ba2321b866428aa04360376e6a390063570"
      adversary = "-"
   strings:
      $s1 = { 50 e8 98 42 00 00 83 c4 04 a3 74 9a 4b 00 85 c0 75 01 c3 56 33 f6 e8 4c 87 01 00 85 c0 7e 24 57 8b 3d a4 e1 47 00 90 6a 00 6a 00 6a 00 ff d7 8b 0d 74 9a 4b 00 89 04 b1 46 e8 29 87 01 00 3b f0 7c e5 5f 68 90 23 40 00 e8 7a 89 01 00 68 60 23 40 00 e8 }
      $s2 = { 6a 00 8b f7 8b 56 24 8b 46 20 8b 7c 24 2c 6a 00 52 50 e8 7b 0e 00 00 8b fe 8d 8c 24 48 09 00 00 51 6a 00 68 7c f2 4a 00 8d 94 24 54 0d 00 00 52 ff 15 28 e0 47 00 85 c0 75 41 8b 74 24 20 8b 7c 24 0c 50 e8 ba 0d 00 00 8d 5f 20 8d a4 24 00 00 00 00 8b 33 8b 7b 04 57 8b c6 03 44 24 14 56 8b cf 13 4c 24 1c 51 50 53 ff 15 24 e0 47 00 3b c6 75 e0 3b d7 75 dc e9 1c 05 00 00 8d 94 24 48 09 00 00 68 18 ef 4a }
      $s3 = { ff 15 4c e0 47 00 83 f8 7a 0f 85 89 00 00 00 8b 45 f8 3d 00 02 00 00 77 7f 8d 70 01 83 e6 fe 8d 46 02 89 75 f8 e8 91 02 ff ff 8b fc 8d 4d f8 51 56 57 6a 02 53 ff 15 d4 e1 47 00 85 c0 74 59 8b 45 f8 40 83 e0 fe 89 45 f8 d1 e8 33 d2 68 50 ff 47 00 57 66 89 14 47 e8 4d e8 05 00 83 c4 08 f7 d8 1b c0 f7 d8 8d 65 ec 5f 5e 5b 8b 4d fc }
      $s4 = { 6a 00 6a 00 53 68 b0 27 40 00 6a 00 6a 00 ff 15 1c e0 47 00 8b 4c 24 10 8b 97 30 04 00 00 89 04 8a 41 3b 4d 10 89 4c 24 10 0f 8c 36 ff ff ff 33 c0 }
   condition:
      uint16(0) == 0x5A4D and filesize > 90KB and all of ($s*)
}
