rule MAL_IceXLoader_Nov_2022_1 : icexloader loader nim v3
{
    meta:
        description = "Detect IceXLoader loader (nim version) v3.3.3"
        author = "Arkbird_SOLG"
        date = "2022-11-10"
        reference = "https://minerva-labs.com/blog/new-updated-icexloader-claims-thousands-of-victims-around-the-world/"
        hash1 = "0911819d0e050ddc5884ea40b4b39a716a7ef8de0179d0dfded9f043546cede9"
        hash2 = "0feba92ff632640e738c770d3eb69ee1e287a54fb86c50bbcd2d0a9114b8539c"
        hash3 = "29c7d7d36a0c8acec88ff7aa34adc0f9240270a85e330fd2336408e1f0d52c21"
        tlp = "Clear"
        adversary = "-"
    strings:
        $s1 = { 70 6f 77 65 72 73 68 65 6c 6c 20 2d 43 6f 6d 6d 61 6e 64 20 53 65 74 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 44 69 73 61 62 6c 65 52 65 61 6c 74 69 6d 65 4d 6f 6e 69 74 6f 72 69 6e 67 20 24 74 72 75 65 }
        $s2 = { 40 5c 5c 2e 5c 70 69 70 65 5c 73 74 64 69 6e 00 00 0f 00 00 00 0f 00 00 40 5c 5c 2e 5c 70 69 70 65 5c 73 74 64 6f 75 74 }
        $s3 = { 40 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 }
        $s4 = { 40 4d 75 74 65 78 5f 49 43 45 5f 58 }
        $s5 = { 89 e5 83 ec ( 28 e8 5e ff ff ff 8d 45 f4 c7 45 | 18 c7 45 f4 ff 00 00 00 c7 05 60 ) f4 ( 23 8d 41 00 89 04 24 e8 c6 97 fe ff 8b 45 f4 ff d0 | 43 00 01 00 00 00 e8 2c 00 00 00 89 45 f4 8b 45 f4 ) c9 c3 55 89 e5 83 ec }
    condition:
        uint16(0) == 0x5A4D and filesize > 50KB and all of ($s*) 
}
