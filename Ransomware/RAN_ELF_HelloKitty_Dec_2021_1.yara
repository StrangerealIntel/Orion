rule RAN_ELF_HelloKitty_Dec_2021_1
{
    meta:
        description = "Detect the ELF version of HelloKitty ransomware"
        author = "Arkbird_SOLG"
        date = "2021-12-20"
        reference = "Internal Research"
        hash1 = "754f2022b72da704eb8636610c6d2ffcbdae9e8740555030a07c8c147387a537"
        hash2 = "8f3db63f70fad912a3d5994e80ad9a6d1db6c38d119b38bc04890dfba4c4a2b2"
        hash3 = "ca607e431062ee49a21d69d722750e5edbd8ffabcb54fa92b231814101756041"
        hash4 = "b4f90cff1e3900a3906c3b74f307498760462d719c31d008fc01937f5400fb85"
        tlp = "Clear"
        adversary = "RAAS"
    strings:
        $s1 = { 55 73 61 67 65 3a 25 73 20 5b 2d 6d 20 28 [0-2] 31 30 2d 32 30 2d 32 35 2d 33 33 2d 35 30 29 20 [0-5] 5d 20 53 74 61 72 74 20 50 61 74 68 20 0a 00 77 6f 72 6b }
        $s2 = "esxcli vm process kill -t=force -w=%d" ascii
        $s3 = { 25 6c 64 20 2d 20 46 69 6c 65 73 20 46 6f 75 6e 64 20 20 0a 00 6d 61 69 6e 3a 25 64 0a 00 54 6f 74 61 6c 20 45 6c 61 70 73 65 64 3a 20 25 66 20 73 65 63 6f 6e 64 73 0a 00 54 6f 74 61 6c 20 43 72 79 70 74 65 64 3a 20 25 64 09 45 72 72 6f 72 3a 20 25 64 }
        $s4 = { 46 69 6c 65 20 4c 6f 63 6b 65 64 3a 25 73 20 50 49 44 3a 25 64 0a 00 6b 69 6c 6c 20 2d 39 20 25 64 00 65 78 65 63 5f 70 69 70 65 3a 25 73 20 0a 00 65 72 72 6f 72 20 4c 6f 63 6b 20 66 69 6c 65 3a 25 73 0a 00 }
        $s5 = { 65 72 72 6f 72 20 6c 6f 63 6b 5f 65 78 63 6c 75 73 69 76 65 6c 79 3a 25 73 20 6f 77 6e 65 72 20 70 69 64 3a 25 64 0a 00 63 72 3a 25 64 20 66 3a 25 73 0a 00 [2-5] 3a 25 64 20 6c 3a 25 64 20 66 3a 25 73 }
    condition:
      uint32(0) == 0x464C457F and filesize > 30KB and 4 of ($s*) 
}

