rule RAN_Hive_March_2022_2 : hive v5 x86
{
    meta:
    description = "Detect Rust version of Hive ransomware (x86 version)"
    author = "Arkbird_SOLG"
    reference = "Internal Research"
    date = "2022-03-27"
    hash1 = "206de75058a7dfa0b96784965baab63a137f2e89a97e623842e7d0bb3f12c2fc"
    hash2 = "a464ae4b0a75d8673cc95ea93c56f0ee11120f71726cc891f9c7e8d4bec53625"
    hash3 = "8b8814921dc2b2cb6ea3cfc7295803c72088092418527c09b680332c92c33f1f"
    hash4 = "bd7f4d6a3f224536879cca70b940b16251c56707124d52fb09ad828a889648cd"
    tlp = "Clear"
    adversary = "RAAS"
  strings:
      $s1 = { 5c 00 5c 00 3f 00 5c 00 00 00 5c 00 5c 00 3f 00 5c 00 55 00 4e 00 43 00 5c 00 5c 5c 2e 5c 70 69 70 65 5c 5f 5f [4] 5f 61 6e 6f 6e 79 6d 6f 75 73 5f 70 69 70 65 31 5f 5f 2e [3] 00 [3] 00 }
      $s2 = { b0 01 8d 65 f4 5e 5f 5b 5d c3 68 [3] 00 6a 00 6a 00 e8 [2] 00 00 85 c0 74 ?? 89 c1 31 c0 f0 0f b1 0d [3] 00 0f 84 ?? fd ff ff 89 c6 51 e8 [2] 00 00 89 f1 e9 ?? fd ff ff 80 7c 24 0e 00 75 4e 8b 4f 18 8b 57 1c c7 84 24 80 01 00 00 [3] 00 c7 84 24 84 01 00 00 01 00 00 00 c7 84 24 88 01 00 00 00 00 00 00 c7 84 24 90 01 00 00 }
      $s3 = { a1 [3] 00 85 c0 75 37 0f 57 c0 0f 29 44 24 40 6a 02 6a 10 8d 44 24 48 50 6a 00 e8 [2] 00 00 85 c0 0f 85 ?? 07 00 00 8b 44 24 40 87 05 [3] 00 eb cb 66 2e 0f 1f 84 00 00 00 00 00 90 b8 01 00 00 00 8d 8c 24 ?? 00 00 00 8d }
      $s4 = { a1 [3] 00 89 45 d4 c7 45 d8 00 00 00 00 89 45 cc c7 45 dc 00 00 00 00 6a 00 6a 08 e8 [2] 00 00 83 f8 ff 0f 84 ?? 02 00 00 89 ?? 8d 85 ?? fb ff ff 68 24 04 00 00 6a 00 50 e8 [2] 00 00 83 c4 0c 8d 85 ?? fb ff ff c7 85 ?? fb ff ff 28 04 00 00 50 ?? e8 [2] 00 00 83 f8 01 0f 85 ?? 02 00 00 c7 45 d0 00 00 00 00 89 ?? c0 [13] 8b [2] 8b }
    condition:
      uint16(0) == 0x5A4D and filesize > 60KB and all of ($s*)
}
