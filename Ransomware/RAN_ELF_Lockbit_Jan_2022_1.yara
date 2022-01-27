rule RAN_ELF_Lockbit_Jan_2022_1
{
   meta:
      description = " Detected ELF version of Lockbit ransomware"
      author = "Arkbird_SOLG"
      reference = "https://www.trendmicro.com/en_us/research/22/a/analysis-and-Impact-of-lockbit-ransomwares-first-linux-and-vmware-esxi-variant.html"
      date = "2022-01-27"
      hash1 = "67df6effa1d1d0690c0a7580598f6d05057c99014fcbfe9c225faae59b9a3224"
      hash2 = "ee3e03f4510a1a325a06a17060a89da7ae5f9b805e4fe3a8c78327b9ecae84df"
      hash3 = "f3a1576837ed56bcf79ff486aadf36e78d624853e9409ec1823a6f46fd0143ea"
      tlp = "white"
      adversary = "RAAS"
   strings:
      $s1 = { be b0 00 00 00 bf 01 00 00 00 e8 [2] ff ff 48 85 c0 48 89 c3 74 ba 48 8d 78 10 31 f6 4c 89 a0 a0 00 00 00 4c 8d ac 24 88 00 00 00 31 ed e8 [2] ff ff 48 8d 7b 38 31 f6 e8 [2] ff ff 48 8d 7b 68 31 f6 e8 [2] ff ff 48 c7 03 00 00 00 00 48 c7 43 08 00 00 00 00 90 31 f6 48 89 d9 ba [2] 40 00 4c 89 ef 48 83 c5 01 e8 [2] ff ff 48 8b bc 24 88 00 00 00 e8 [2] ff ff }
      $s2 = { 48 81 ec 58 08 00 00 48 8d 5c 24 30 4c 8d ?? 24 30 04 00 00 4c 8d bc 24 48 08 00 00 e8 [2] ff ff 89 c7 4c 8d ?? 24 30 08 00 00 e8 }
      $s3 = { 49 8b 75 00 31 ff 4d 89 f9 45 89 f0 b9 02 00 00 00 ba 03 00 00 00 e8 [2] ff ff 48 83 f8 ff 49 89 c4 0f 84 ?? ff ff ff 48 83 c4 38 4c 89 }
      $s4 = { 48 8d b4 24 c8 07 00 00 48 89 d7 e8 ?? ee ff ff 4c 8b 8c 24 e8 06 00 00 4c 8b 84 24 c8 07 00 00 48 89 c1 48 8b 94 24 c0 06 00 00 44 89 ?? 48 89 df e8 ?? f7 ff ff e9 ?? ff ff ff 0f 1f ?? 00 }
   condition:
      uint32(0) == 0x464C457F and filesize > 120KB and all of ($s*)
}
