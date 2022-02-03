rule RAN_Sugar_Jan_2022_2
{
   meta:
        description = "Detect the Sugar ransomware (Unpacked)"
        author = "Arkbird_SOLG"
        reference = "https://medium.com/walmartglobaltech/sugar-ransomware-a-new-raas-a5d94d58d9fb"
        date = "2022-02-02"
        hash1 = "4a97bc8111631795cb730dfe7836d0afac3131ed8a91db81dde5062bb8021058"
        hash2 = "43e4a6830f54f3bd039b90f0a27ad19a9f2bb673ab990f34dc201c3b102e056a"
        tlp = "White"
        adversary = "RAAS"
   strings:
        $s1 = { 68 00 00 00 f0 6a 01 a1 54 13 42 00 8b 00 50 6a 00 8d 45 fc 50 e8 ed bc ff ff 84 c0 75 1a 68 08 00 00 f0 6a 01 a1 54 13 42 00 8b 00 50 6a 00 8d 45 fc 50 e8 cf bc ff ff 83 7d fc 00 76 49 33 c0 55 68 35 47 41 00 64 ff 30 64 89 20 8b c3 8b d6 e8 da f3 fe ff 8b c3 e8 9f f2 fe ff 50 56 8b 45 fc 50 e8 b0 bc ff ff 33 c0 5a 59 59 64 89 10 68 3c }
        $s2 = { 56 57 89 45 fc 8d b5 e4 fd ff ff 33 c0 55 68 8b c5 41 00 64 ff 30 64 89 20 8b c6 ba f4 01 00 00 e8 23 8e fe ff 8d 45 f2 ba 0a 00 00 00 e8 16 8e fe ff 8b 45 fc 8b 15 1c 19 41 00 e8 80 86 fe ff 8d 45 ec 8b 15 1c 19 41 00 e8 72 86 fe ff 8d 45 e8 8b 15 1c 19 41 00 e8 64 86 fe ff 56 68 e8 03 00 00 e8 e9 8c fe ff 33 db 8d 45 f2 33 c9 ba 0a 00 00 00 e8 70 67 fe ff 33 c0 8a 14 1e 88 54 05 f2 40 43 80 3c 1e 00 74 05 83 f8 09 7e ec 8b 45 ec e8 4a 83 fe ff 40 50 8d 45 ec b9 01 00 00 00 8b 15 1c 19 41 }
        $s3 = { 89 03 33 c0 89 07 8d 45 f4 50 8b 45 fc 50 6a 00 56 6a 02 e8 9f 94 fe ff 85 c0 0f 85 87 00 00 00 c7 45 f0 00 40 00 00 8b 45 f0 e8 50 6c fe ff 89 03 83 3b 00 74 68 83 3b 00 74 39 c7 07 ff ff ff ff 8b 03 33 c9 8b 55 f0 e8 42 6e fe ff 8d 45 f0 50 8b 03 50 57 8b 45 f4 50 e8 49 94 fe ff 8b f0 81 fe ea 00 00 00 75 13 8b c3 8b 55 f0 e8 5d 6c fe ff eb 07 be ea 00 00 00 eb 08 81 fe ea 00 00 00 74 b3 85 f6 0f 94 45 fb 80 7d fb 00 75 0f 8b 03 e8 19 6c fe ff 33 c0 89 03 33 c0 89 07 8b 45 f4 50 e8 f8 93 fe ff }
        $s4 = { 6a 00 6a 00 6a 03 6a 00 6a 00 6a 50 8b 45 fc e8 2a 01 ff ff 50 8b 45 f4 50 e8 ac 25 ff ff 89 45 f0 83 7d f0 00 0f 84 f9 00 00 00 6a 00 68 00 07 00 84 6a 00 6a 00 68 78 3b 41 00 8b 45 e4 e8 fb 00 ff ff 50 68 84 3b 41 00 8b 45 f0 50 e8 60 25 ff ff 89 45 ec 83 7d ec 00 0f 84 bc 00 00 00 8b 45 f8 e8 d7 fe fe ff 50 8b 45 f8 e8 ce 00 ff ff 50 6a 2f 68 8c 3b 41 00 8b 45 ec 50 e8 39 25 ff ff }
    condition:
        uint16(0) == 0x5A4D and filesize > 30KB and all of ($s*) 
}
