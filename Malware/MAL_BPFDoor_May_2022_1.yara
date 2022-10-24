rule MAL_BPFDoor_May_2022_1 : apt bpfdoor controller redmenshen x64
{
   meta:
        description = "Detect BPFDoor used by Red Menshen"
        author = "Arkbird_SOLG"
        reference = "https://twitter.com/jcksnsec/status/1522163033585467393"
        date = "2022-05-06"
        hash1 = "591198c234416c6ccbcea6967963ca2ca0f17050be7eed1602198308d9127c78"
        hash2 = "1925e3cd8a1b0bba0d297830636cdb9ebf002698c8fa71e0063581204f4e8345"
        hash3 = "93f4262fce8c6b4f8e239c35a0679fbbbb722141b95a5f2af53a2bcafe4edd1c"
        tlp = "Clear"
        adversary = "Red Menshen"
   strings:
        $s1 = { 48 [2-5] 48 [2-3] e8 [2] ff ff 89 45 ?? 83 ( 7d ?? ff 75 1c 48 8b 75 98 bf 17 35 40 00 | ( 7d ?? ff 75 23 b8 98 32 40 00 48 8b 55 88 48 89 d6 48 | 7d e8 00 74 5d bf 06 36 40 00 e8 fd ec ff ff 8b 45 e8 be 03 00 00 00 ) 89 c7 ) b8 00 00 00 00 e8 [2] ff ff }
        $s2 = { e8 [2] ff ff [1-3] 00 00 00 00 e9 [2] 00 00 48 8d 45 ?? 0f b6 00 84 c0 75 }
        $s3 = { 0f b7 4d ?? 8b 55 ?? 8b [2] 48 8d [4-7] e8 [0-2] ff ff eb ?? 0f b7 4d ?? 8b 55 ?? 8b [2] 48 8d [2-7] e8 [2] ff ff eb ?? 0f b7 4d ?? 8b 55 ?? 8b }
        $s4 = { 8b [2] bf ff ff [2-4] fd ff ff 48 8d [2-5] bf 00 00 00 00 e8 [2] ff ff 48 8b 45 ?? 48 89 85 ?? ff ff ff 48 8b 45 ?? 48 89 85 ?? ff ff ff 48 8b 45 ?? 48 89  }
   condition:
        uint32(0) == 0x464C457F and filesize > 10KB and all of ($s*)
}
