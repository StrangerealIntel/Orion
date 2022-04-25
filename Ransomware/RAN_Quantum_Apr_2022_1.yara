rule RAN_Quantum_Apr_2022_1 : ransomware quantum x64
{
   meta:
        description = "Detect the quantum ransomware (x64)"
        author = "Arkbird_SOLG"
        reference = "Internal Research"
        date = "2022-04-10"
        hash1 = "1d64879bf7b1c7aea1d3c2c0171b31a329d026dc4e2f1c876d7ec7cae17bbc58"
        hash2 = "6143d920ebdd5e9b1db7425916417c0896139f425493a8fcd63d62dac80779f1"
        hash3 = "0789a9c0a0d4f3422cb4e9b8e64f1ba92f7b88e2edfd14b7b9a7f5eee5135a4f"
        hash4 = "5a9028518866ce9fc3847f4704060f71e1c572132ec3f1845f29023a659f9daf"
        tlp = "White"
        adversary = "RAAS"
   strings:
        $s1 = { 48 89 ?? 24 60 4c [2-4] 4c 89 74 24 58 48 [2-5] 24 ?? 48 [0-3] 89 5c 24 }
        $s2 = { 48 83 ec 40 4d 8b f1 c7 40 dc 00 40 00 00 4c 8b ca 48 8d 40 e0 33 d2 48 89 44 24 20 4d 8b f8 8b e9 8d 4a 02 44 8d 42 13 [5-6] 33 ff 85 c0 0f 85 ?? 00 00 00 83 4c 24 30 ff 8b 5c 24 34 48 85 db 0f 84 ?? 00 00 00 ff 15 [2] 00 00 4c 8d 43 01 ba 08 00 00 00 48 8b c8 ff 15 [2] 00 00 48 8b d8 48 85 c0 0f 84 ?? 00 00 00 48 8b 4c 24 38 4c 8d 4c 24 34 4c 8b c0 48 8d 54 24 30 [5-6] 8b f0 85 c0 74 1d 3d ea 00 00 00 75 6d ff 15 [2] 00 00 4c 8b c3 33 d2 48 8b c8 ff 15 }
        $s3 = { 45 33 c9 48 8d 54 24 30 45 8d 41 0c 41 8d 49 01 ff 15 [2] 00 00 85 c0 75 22 66 83 7c 24 30 09 48 8d 15 [2] 00 00 b8 40 00 00 00 41 8b ce 44 8d 40 e0 44 0f 44 c0 e8 [4] bb fa 00 00 00 48 8d 95 [2] 00 00 48 8d 8d d0 00 00 00 89 9d [2] 00 00 ff 15 [2] 00 00 85 c0 74 24 8b 85 [2] 00 00 4c 8d 85 d0 00 00 00 48 8d 15 [2] 00 00 41 8b ce 66 89 b4 45 d0 00 00 00 e8 [4] 48 8d 95 [2] 00 00 89 9d [2] 00 00 48 8d 8d d0 00 00 00 ff 15 [2] 00 00 85 c0 74 24 8b 85 [2] 00 00 4c 8d 85 d0 00 00 00 48 8d 15 [2] 00 00 41 8b ce 66 89 b4 45 d0 00 00 00 e8 }
        $s4 = { 48 83 ec 20 [0-3] 8b f2 48 8b f9 ff 15 [2] 00 00 83 f8 04 [2-5] 4c 8b c7 [0-5] 0f ba e6 13 73 ?? 48 8d 15 [2] 00 00 }
   condition:
       uint16(0) == 0x5A4D and all of ($s*)
}
