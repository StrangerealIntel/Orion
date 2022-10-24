rule TA_Lorec53_OutSteel_Feb_2022_1
{
   meta:
        description = "Detect the OutSteel malware used by Lorec53 (aka Lori Bear/UAC-0056)"
        author = "Arkbird_SOLG"
        reference = "https://cert.gov.ua/article/18419"
        date = "2022-02-16"
        hash1 = "506c90747976c4cc3296a4a8b85f388ab97b6c1cfae11096f95977641b8f8b6f"
        hash2 = "29decd1e88b297aa67fef6e14e39889cfd2454c581b9371a1003b63a28324d0f"
        hash3 = "5fd4e486bd7e12454f67ba8fcdaa9afc88b4d1c29705b0cffc9d32000700d314"
        hash4 = "d0aad99f10bdd6f6af2f7a0f6c319ed7d126de4d1ff44ca86858e7ffc17cc39b"
        tlp = "Clear"
        adversary = "Lorec53"
        // Note : This stealer is very basic stealer compiled with autoit to exe and can have easily false positives in attribution
   strings:
        $s1 = { 8d 45 ec c7 45 ec 04 01 00 00 50 8d 85 d0 fc ff ff 50 ff 15 0c f3 48 00 e9 65 fe ff ff 68 04 01 00 00 8d 85 d0 fc ff ff 50 ff 15 10 f3 48 00 85 c0 0f 84 24 aa fc ff e9 46 fe ff ff a1 28 74 4c 00 68 04 01 00 00 80 78 34 00 8d 85 d0 fc ff ff 50 0f 84 25 fe ff ff 8d 4d dc 89 7d dc 89 7d e4 e8 7c a5 03 00 ff d0 83 7d } 
        $s2 = { ff 75 14 ff 75 10 ff 75 0c 50 e8 c2 03 00 00 84 c0 0f 84 af 01 00 00 6a 02 59 84 4d 14 74 29 8d 45 10 50 6a 01 51 53 53 ff 75 fc ff 15 40 f0 48 00 85 c0 0f 84 8d 01 00 00 ff 75 fc ff 15 5c f3 48 00 8b 45 10 89 45 fc 68 00 00 06 00 53 68 24 95 4b 00 ff 15 b0 f6 48 00 8b f0 85 f6 0f 84 63 01 00 00 83 fe ff 0f 84 5a 01 00 00 ff 15 ac f6 48 00 56 89 45 ec ff 15 a8 f6 48 00 85 c0 0f 84 42 01 00 00 68 81 00 06 00 53 53 68 34 95 4b 00 ff 15 a4 f6 48 00 8b f8 85 ff 0f 84 }
        $s3 = { 8d 4c 24 38 e8 e2 91 f9 ff 8b 45 08 8b 40 04 8b 30 8b ce e8 a3 b3 f9 ff 8b 4e 08 8d 54 24 38 e8 ae 62 f9 ff 68 fe ff 00 00 e8 ec 29 fb ff 59 50 8d 4c 24 24 e8 79 6d f9 ff 8b 5c 24 20 6a 0a 5e ff 74 24 38 66 89 73 02 68 ff 7f 00 00 53 ff 15 a4 f2 48 00 89 44 24 18 85 c0 0f 84 66 01 00 00 66 39 73 02 0f 84 5c 01 00 00 6a 0c e8 a9 29 fb ff }
        $s4 = { 6a 16 e8 8f 8b f9 ff 0f b7 4d 92 8b f0 51 0f b7 4d 8e 51 0f b7 4d 8c 51 68 10 b7 4b 00 56 ff 15 64 f5 48 00 83 c4 18 e9 99 fc ff ff 89 3b e9 b4 02 00 00 33 ff 80 7d 10 00 57 57 74 47 6a 0e 56 ff 15 88 f6 48 00 33 c9 6a 02 5a 8d 70 01 8b c6 f7 e2 0f 90 c1 f7 d9 0b c8 51 e8 37 8b f9 ff 59 56 50 ff 75 0c 89 45 10 ff 15 6c f6 48 00 85 c0 75 0a ff 75 10 89 }
        $s5 = { 33 03 34 0d 34 17 34 21 34 2b 34 32 34 36 34 3c 34 40 34 46 34 50 34 5a 34 64 34 6e 34 75 34 79 34 7f 34 83 34 89 34 93 34 9d 34 a7 34 b1 34 b8 34 bc 34 c2 34 c6 34 cc 34 d6 34 e0 34 ea 34 f4 34 fb 34 ff 34 05 35 09 35 0f 35 19 }
        $s6 = { 1C ?? 8A FF 5E ?? 88 42 0B E5 3D 48 F0 B0 7B DA 58 FF C0 E3 B0 B0 0B 01 [3] 00 [3] 00 [3] 02 [3] 01 [7] 01 [4] 6D FB FA 03 B3 }
    condition:
        uint16(0) == 0x5A4D and filesize > 650KB and all of ($s*) 
}
