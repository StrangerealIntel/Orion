rule APT_SideWinder_WarHawk_Oct_2022_1 : sidewinder apt warhawk
{
   meta:
      description = "Detects the warhawk implant used by the Sidewinder group"
      author = "Arkbird_SOLG"
      reference = "https://www.zscaler.com/blogs/security-research/warhawk-new-backdoor-arsenal-sidewinder-apt-group-0"
      date = "2022-10-22"
      hash1 = "624c6b56ee3865f4a5792ad1946a8e86b876440a5af3bac22ac1dee92f1b7372"
      hash2 = "7d3574c62df44b74337fc74ec7877792b4ffa1486a49bb19668433c3ca8836b5"
      tlp = "Clear"
      adversary = "SideWinder"
   strings:
      $s1 = { a1 04 ?? 42 00 33 c5 89 45 fc 8b 45 08 53 56 57 33 db 89 [2-5] 53 53 53 6a 01 68 [2] 42 00 8b f2 c7 ?? f8 [0-3] 00 00 00 00 8b f9 ff 15 [2] 41 00 53 53 6a 03 53 53 6a 50 68 80 ?? 42 00 50 89 ?? e8 [0-3] ff 15 [2] 41 00 }
      $s2 = { 7b 20 5c 22 6e 61 6d 65 5c 22 3a 20 5c 22 25 73 5c 22 2c 20 5c 22 73 69 7a 65 5c 22 3a 20 5c 22 5c 22 2c 20 5c 22 6d 6f 64 5c 22 3a 20 5c 22 25 73 5c 22 2c 20 5c 22 74 79 70 65 5c 22 3a 20 5c 22 46 69 6c 65 20 66 6f 6c 64 65 72 5c 22 20 7d }
      $s3 = { 50 6a 40 ff 15 [2] 41 00 [3-4] 42 00 [3-5] 42 00 68 [2] 42 00 68 [2] 42 00 [3-5] 42 00 56 ff 15 }
      $s4 = { 7b 20 22 5f 68 77 69 64 22 3a 20 22 25 73 22 2c 20 22 5f 63 6d 64 22 3a 20 22 74 72 75 65 22 20 7d }
   condition:
      uint16(0) == 0x5a4d and filesize > 200KB and all of ($s*)
}
