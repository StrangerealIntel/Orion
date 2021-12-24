rule RAN_Intercobros_Dec_2021_1
{
    meta:
        description = "Detect the Intercobros ransomware"
        author = "Arkbird_SOLG"
        date = "2021-12-21"
        reference = "Internal Research"
        hash1 = "ade5780b02f010a91f0684089100035366af865caba9c6beb66a271ccc89f2ae"
        tlp = "white"
        adversary = "Intercobros"
        level="Experimental"
    strings:
        $s1 = { 8b 45 f8 a3 98 93 44 00 68 94 08 44 00 e8 ff a7 ff ff 83 c4 04 68 f8 08 44 00 e8 b2 a7 ff ff 83 c4 04 68 18 09 44 00 e8 a5 a7 ff ff 83 c4 04 68 40 09 44 00 e8 98 a7 ff ff 83 c4 04 68 68 09 44 00 e8 8b a7 ff ff 83 c4 04 68 8c 09 44 00 e8 7e a7 ff ff 83 c4 04 68 b0 09 44 00 e8 71 a7 ff ff 83 c4 04 68 d0 09 44 00 e8 64 a7 ff ff 83 c4 04 68 f0 09 44 00 e8 57 a7 ff ff 83 c4 04 68 18 0a 44 00 e8 4a a7 ff ff 83 c4 04 68 88 0a 44 00 e8 3d a7 ff ff 83 c4 04 68 5c 0a 44 00 e8 30 a7 ff ff 83 c4 04 68 c8 0a 44 00 e8 23 a7 ff ff 83 c4 04 68 e8 0a 44 00 e8 16 a7 ff ff 83 c4 04 68 f8 0a 44 00 e8 09 a7 ff ff 83 c4 04 68 34 0b 44 00 e8 fc a6 ff ff 83 c4 04 68 4c 0b 44 00 e8 ef a6 ff ff 83 c4 04 68 5c 0b 44 00 e8 e2 a6 ff ff 83 c4 04 68 6c 0b 44 00 e8 d5 a6 ff ff 83 c4 04 68 80 0b 44 00 e8 c8 a6 ff ff 83 c4 04 68 9c 0b 44 00 e8 bb a6 ff ff 83 c4 04 68 b0 0b 44 00 e8 ae a6 ff ff 83 c4 04 68 c4 0b 44 00 e8 a1 a6 ff ff 83 c4 04 68 f0 0b 44 00 e8 94 a6 ff ff 83 c4 04 68 28 0c 44 00 e8 87 a6 ff ff 83 c4 04 68 38 0c 44 00 e8 7a a6 ff ff 83 c4 04 68 54 0c 44 00 e8 6d a6 ff ff 83 c4 04 68 70 0c 44 00 e8 60 a6 ff ff 83 c4 04 68 84 0c 44 00 e8 53 a6 ff ff 83 c4 04 68 98 0c 44 00 e8 46 a6 ff ff 83 c4 04 68 b4 0c 44 00 e8 39 a6 ff ff 83 c4 04 68 d0 0c 44 00 e8 2c a6 ff ff 83 c4 04 68 e0 0c 44 00 e8 1f a6 ff ff 83 c4 04 68 f8 0c 44 00 e8 12 a6 ff ff 83 c4 04 68 10 0d 44 00 e8 05 a6 ff ff 83 c4 04 68 40 0d 44 00 e8 f8 a5 ff ff 83 c4 04 68 7c 0d 44 00 e8 eb a5 ff ff 83 c4 04 68 a8 0d 44 00 e8 de a5 ff ff 83 c4 04 68 d0 0d 44 00 e8 d1 a5 ff ff 83 c4 04 68 f4 0d 44 00 e8 c4 a5 ff ff 83 c4 04 68 2c 0e 44 00 e8 b7 a5 ff ff 83 c4 04 68 58 0e 44 00 e8 aa a5 ff ff 83 c4 04 68 80 0e 44 00 e8 9d a5 ff ff 83 c4 04 68 94 0e 44 00 e8 90 a5 ff ff 83 c4 04 68 ac 0e 44 00 e8 83 a5 ff ff }
        $s2 = { 8b 45 08 c7 40 50 10 00 00 00 8b 4d 08 83 c1 50 51 8b 55 08 83 c2 30 52 ff 15 80 c0 43 00 8b 45 08 83 c0 54 50 ff 15 84 c0 43 00 68 d8 b3 44 00 68 e0 6b 40 00 68 00 08 00 00 8b 4d 10 51 8b 55 0c 52 6a 70 8b 45 08 50 8d 4d e0 51 e8 4d fb fc ff 83 }
        $s3 = { 8d 45 c4 50 8b 4d 08 51 6a 00 6a 01 6a 01 e8 b2 51 00 00 89 45 c0 83 7d c0 00 0f 85 10 02 00 00 c7 45 e0 00 10 00 00 8b 55 e0 83 c2 10 83 e2 f0 83 fa 10 73 09 c7 45 d4 10 00 00 00 eb 0c 8b 45 e0 83 c0 10 83 e0 f0 89 45 d4 8b 4d d4 51 6a 40 ff 15 90 c0 43 00 89 45 f0 83 7d f0 }
        $s4 = { 68 48 92 44 00 68 40 01 00 00 8b 15 28 92 44 00 52 ff 15 14 c0 43 00 85 c0 74 14 68 40 01 00 00 68 48 92 44 00 e8 bd 06 00 00 83 c4 08 eb 0f ff 15 b4 c0 43 00 a3 24 92 44 00 33 c0 eb 12 e8 04 08 00 00 8b 45 ec a3 8c 93 44 00 b8 }
        $s5 = "is_it_possible_return_back lost documents.txt" wide
    condition:
      uint16(0) == 0x5A4D and filesize > 80KB and 4 of ($s*)     
}