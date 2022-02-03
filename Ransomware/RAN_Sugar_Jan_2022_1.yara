rule RAN_Sugar_Jan_2022_1
{
   meta:
        description = "Detect the Sugar ransomware (Packed)"
        author = "Arkbird_SOLG"
        reference = "https://medium.com/walmartglobaltech/sugar-ransomware-a-new-raas-a5d94d58d9fb"
        date = "2022-02-02"
        hash1 = "315045e506eb5e9f5fd24e4a55cda48d223ac3450037586ce6dab70afc8ddfc9"
        hash2 = "09ad72ac1eedef1ee80aa857e300161bc701a2d06105403fb7f3992cbf37c8b9"
        hash3 = "1d4f0f02e613ccbbc47e32967371aa00f8d3dfcf388c39f0c55a911b8256f654"
        tlp = "White"
        adversary = "RAAS"
   strings:
        $s1 = { 6a 40 68 00 30 00 00 8b 45 f8 ff 70 50 6a 00 ff 15 04 20 40 00 89 45 f4 83 7d f4 00 0f 84 13 02 00 00 8b 45 f8 ff 70 54 ff 75 08 ff 75 f4 e8 4a f8 ff ff 83 c4 0c 83 65 e4 00 eb 07 8b 45 e4 40 89 45 e4 8b 45 f8 0f b7 40 06 48 39 45 e4 7f 3b 8b 45 e0 8b 4d 08 03 48 3c 6b 45 e4 28 8d 84 01 f8 00 00 00 89 45 d8 8b 45 d8 ff 70 10 8b 45 d8 8b 4d 08 }
        $s2 = { 8b ec 6a 04 68 00 30 00 00 ff 75 08 6a 00 ff 15 04 20 40 00 5d c3 55 8b ec 68 00 80 00 00 6a 00 ff 75 08 ff 15 08 20 40 00 5d c3 55 8b ec 51 ff 75 10 e8 c8 ff ff ff 8b d0 59 85 d2 74 2e 8b 45 0c 57 33 ff 48 8b cf 89 45 fc 39 4d 10 76 1c 53 8b 5d 08 8a 04 1f 88 04 11 8d 47 01 33 ff 41 3b 45 fc }
        $s3 = { 8b 46 3c 05 f8 00 00 00 03 c2 03 c6 68 00 10 40 00 50 89 45 f8 ff 15 1c 20 40 00 85 c0 75 1d 8b 45 f8 6a 04 68 00 30 00 00 ff 70 10 57 ff 15 04 20 40 00 8b c8 89 4d f4 85 c9 75 1c 8b 4d 08 8b 55 fc 41 0f b7 44 33 06 83 c2 28 48 89 4d 08 89 55 fc 3b c8 7e aa eb 18 8b 45 f8 ff 70 10 8b 40 0c 03 c6 50 51 e8 e3 f8 }
        $s4 = { 8b ec 83 ec 1c 6a 1c 8d 45 e4 50 68 82 17 40 00 ff 15 0c 20 40 00 8b 45 e8 c9 c3 55 8b ec 83 ec 40 53 c6 45 ff 00 8b 45 08 89 45 e0 8b 45 e0 0f b7 00 3d 4d 5a 00 00 0f 85 50 02 00 00 8b 45 e0 8b 4d 08 03 48 3c 89 4d f8 8b 45 f8 81 38 50 45 00 00 0f 85 35 02 00 00 6a 40 68 }
    condition:
        uint16(0) == 0x5A4D and filesize > 30KB and all of ($s*) 
}
