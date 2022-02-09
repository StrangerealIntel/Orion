rule APT_Molerats_NimbleMamba_Jan_2022_1
{
   meta:
        description = "Detect the NimbleMamba backdoor used by Molerats group"
        author = "Arkbird_SOLG"
        reference = "https://www.proofpoint.com/us/blog/threat-insight/ugg-boots-4-sale-tale-palestinian-aligned-espionage"
        date = "2022-02-09"
        hash1 = "430c12393a1714e3f5087e1338a3e3846ab62b18d816cc4916749a935f8dab44"
        hash2 = "2a559a5178e0803c0a4067376cf279d00cade84b37158f03b709e718d34f65f9"
        hash2 = "c61fcd8bed15414529959e8b5484b2c559ac597143c1775b1cec7d493a40369d"
        tlp = "White"
        adversary = "Molerats"
   strings:
        $s1 = { 72 f3 00 00 70 38 [2] 00 00 [3] 00 [4] 00 [3] 01 00 [4] 00 ?? 38 [2] 00 00 [2] 01 00 [3] 00 00 ?? 72 ?? 01 00 70 38 [2] 00 00 [3] 00 ?? 38 [2] 00 00 [3] 00 00 }
        $s2 = { 72 1d 02 00 70 7e 0a 00 00 04 72 1d 02 00 70 38 [2] 00 00 38 [2] 00 00 38 [2] 00 00 [3] 00 [4] 00 [4] 00 [3] 00 00 ?? 72 [2] 00 70 38 [2] 00 00 [3] 00 [3] 01 00 ?? 38 [2] 00 00 [3] 00 }
        $s3 = { 38 2f 01 00 00 38 34 01 00 00 72 6e 04 00 70 38 fd 00 00 00 38 02 01 00 00 38 07 01 00 00 38 bf 00 00 00 38 c0 00 00 00 38 c5 00 00 00 38 ca 00 00 00 38 86 00 00 00 08 6f [2] 00 0a 74 ?? 00 00 01 0d 09 6f [2] 00 0a 09 72 b4 04 00 70 6f [2] 00 0a 6f ?? 00 00 0a 6f [2] 00 0a 72 01 00 00 70 28 [2] 00 0a 15 2c 58 2c 19 16 2d d3 06 09 72 b4 04 00 70 6f [2] 00 0a 6f ?? 00 00 0a 6f [2] 00 0a 09 72 ce 04 00 70 6f [2] 00 0a 6f ?? 00 00 0a 6f [2] 00 0a 72 01 00 00 70 28 [2] 00 0a 2c 16 06 09 72 ce 04 00 70 6f [2] 00 0a 6f ?? 00 00 0a 6f [2] 00 0a 08 6f [2] 00 0a 3a 6f ff ff ff de 16 16 2d 03 08 2c 06 08 6f ?? 00 00 0a 18 2c f1 16 2d f4 16 2d f1 dc de 2a 07 38 3b ff ff ff 6f [2] 00 0a 38 36 ff ff ff 6f [2] 00 0a 38 31 ff ff ff 0c 38 30 ff ff ff 07 2c 06 07 6f ?? 00 00 0a dc 06 13 04 de 20 73 [2] 00 0a 38 f9 fe ff ff 73 [2] 00 0a 38 f4 fe ff ff 0b 38 f3 fe ff ff 26 06 13 04 de 00 11 04 2a 73 [2] 00 0a 38 c7 fe ff ff 0a 38 c6 fe ff }
        $s4 = { 7e [2] 00 0a 72 ?? 07 00 70 38 ?? 00 00 00 14 38 ?? 00 00 00 74 ?? 00 00 01 38 ?? 00 00 00 38 ?? 00 00 00 [4] 00 }
    condition:
        uint16(0) == 0x5A4D and filesize > 50KB and all of ($s*) 
}
