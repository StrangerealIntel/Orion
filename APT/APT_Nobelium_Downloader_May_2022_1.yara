rule APT_Nobelium_Downloader_May_2022_1 : apt nobelium downloader 
{
   meta:
        description = "Detect the new downloader used by Nobelium group"
        author = "Arkbird_SOLG"
        reference1 = "https://twitter.com/ShadowChasing1/status/1522180445789573124"
        reference2 = "https://github.com/Dump-GUY/Malware-analysis-and-Reverse-engineering/blob/main/APT29_C2-Client_Dropbox_Loader/APT29-DropboxLoader_analysis.md"
        date = "2022-05-16"
        hash1 = "6618a8b55181b1309dc897d57f9c7264e0c07398615a46c2d901dd1aa6b9a6d6"
        hash2 = "23a09b74498aea166470ea2b569d42fd661c440f3f3014636879bd012600ed68"
        hash3 = "6fc54151607a82d5f4fae661ef0b7b0767d325f5935ed6139f8932bc27309202"
        tlp = "white"
        adversary = "Nobelium"
   strings:
        $s1 = { 8b 00 ba 5c 00 00 00 89 01 48 8d 8d 10 02 00 00 e8 ?? 26 00 00 48 8b f8 48 85 c0 75 05 48 8b cb eb 10 ba 04 01 00 00 48 8b cf e8 ?? 51 00 00 48 8b c8 33 c0 4c 8d 85 10 02 00 00 f3 aa 48 8d 8d 10 02 00 00 48 8d 15 [2] 01 00 e8 ?? f6 ff ff 48 8d 8d 10 02 00 00 ff 15 [2] 01 00 83 f8 ff 0f 84 b6 00 00 00 b9 10 00 00 00 e8 ?? 13 00 00 4c 8b c8 48 8b f8 33 c0 b9 10 00 00 00 f3 aa 49 8b f9 48 8b d3 0f 1f 84 00 00 00 00 00 42 0f b6 8c 32 [3] 00 48 83 c2 03 88 0f 48 8d 7f 01 48 }
        $s2 = { 48 89 5c 24 38 [3-7] c7 44 24 30 00 00 80 00 [3] 48 89 5c 24 28 49 8b [0-3] cf 48 89 5c 24 20 ff 15 [2] 01 00 48 8b f0 48 85 c0 0f 84 ?? 02 00 00 }
        $s3 = { 48 8d 44 24 50 41 b9 06 00 02 00 45 33 c0 48 89 44 24 20 49 8b d2 48 c7 c1 01 00 00 80 ff 15 [2] 01 00 85 c0 75 40 48 8d 4d f0 ff 15 [2] 01 00 48 8b 4c 24 50 41 b9 01 00 00 00 45 33 c0 48 8b d6 8d 04 45 02 00 00 00 89 44 24 28 48 8d 45 f0 48 89 44 24 20 ff 15 [2] 01 00 48 8b 4c 24 50 ff 15 [2] 01 00 48 8b b4 24 60 06 00 00 4c 8b b4 24 }
        $s4 = { 8d 54 24 48 49 8b cf ff 15 [3] 00 48 8d 54 24 48 49 8b cf ff 15 [3] 00 85 c0 0f 84 f5 00 00 00 48 8d 35 [2] ff ff ff 15 [3] 00 39 44 24 54 0f 85 ba 00 00 00 48 8d 0d }
    condition:
         uint16(0) == 0x5A4D and filesize > 50KB and all of ($s*) 
}
