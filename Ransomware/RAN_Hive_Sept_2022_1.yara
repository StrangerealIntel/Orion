rule RAN_Hive_Sept_2022_1 : hive v5 x64
{
   meta:
        description = "Detect Rust version of Hive v5.4 ransomware (x64 version)"
        author = "Arkbird_SOLG"
        reference = "https://twitter.com/rivitna2/status/1570457232088637441"
        date = "2022-09-18"
        // updated 2022-10-29
        // -> https://twitter.com/rivitna2/status/1586366397156065280
        hash1 = "985c20ab57daa2d8135833f83bb48aebbaee96082dabed5e78329b9fe0b902d7"
        hash2 = "f0e8eeb7582943e3dbb78f3d39e265998e7c82f0ff368603e09382b8f2aa0f80"
        hash3 = "3d984c6d23e6b1440dbc5a3c717ce6b068318e625cedc61b3efdcada82d6861f"
        tlp = "Clear"
        adversary = "RAAS"
   strings:
        $s1 = { b9 0c 00 00 00 48 89 8b 40 03 00 00 48 8b ac 24 ?? 08 00 00 48 89 ab 48 03 00 00 48 8b ac 24 ?? 08 00 00 48 89 ab 50 03 00 00 48 89 8b 58 03 00 00 [6] 00 [6] 00 00 48 }
        $s2 = { 48 89 84 24 [2] 00 00 48 89 94 24 [2] 00 00 66 c7 84 24 [2] 00 00 00 00 c7 84 24 [2] 00 00 01 00 00 00 4c 89 f9 48 8d 94 24 [2] 00 00 e8 [3] ff 48 83 bc 24 [2] 00 00 00 74 16 4c 8b 84 24 [2] 00 00 48 8b 0d [3] 00 31 d2 e8 [3] 00 48 8b 8c 24 [2] 00 00 48 89 f2 e8 [3] 00 4c 89 f9 e8 [3] ff 4d 85 e4 74 11 48 8b 0d [3] 00 31 d2 49 89 e8 e8 [3] 00 48 89 d9 48 89 f2 41 b8 00 7d 00 00 e8 [3] 00 85 c0 0f 85 d8 fe ff ff 48 89 d9 e8 [3] 00 48 8d 8c 24 ?? 00 00 00 e8 [3] ff 48 8d 8c 24 [2] 00 00 e8 [3] ff 48 8d b4 24 [2] 00 00 48 8b 0e 48 8b 56 10 e8 [3] ff }
        $s3 = { 48 01 c2 48 8d 6c 24 40 48 89 45 00 48 89 55 08 66 c7 45 10 00 00 c7 45 18 01 00 00 00 48 8d bc 24 48 01 00 00 48 89 f9 48 89 ea e8 [2] 00 00 48 8b 0f 48 89 5c 24 30 4c 89 64 24 28 4c 89 7c 24 20 31 d2 4d 89 f0 41 b9 ff ff ff ff e8 [2] 0a 00 85 c0 0f 85 ?? 06 00 00 48 8b 8c 24 98 00 00 00 8b 84 24 8c 00 00 00 48 85 c0 0f 84 ?? 06 00 00 48 89 b4 24 d0 00 00 00 48 8d 04 c1 48 89 84 24 d8 00 00 00 0f 57 f6 41 ?? ff ff 00 00 49 ?? 00 00 00 00 00 00 01 00 48 8d 6c 24 70 }
        $s4 = { 48 8b b4 24 b0 00 00 00 48 8b 9c 24 b8 00 00 00 c7 44 24 28 03 00 00 00 48 c7 44 24 20 00 00 00 00 31 c9 31 d2 }
   condition:
        uint16(0) == 0x5A4D and filesize > 60KB and all of ($s*) 
}
