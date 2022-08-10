rule CRIM_FIN13_CMD_Jan_2022_1 : fin13 command execution
{
    meta:
        description = "Detect similiar command execution used by the fin13 group"
        author = "Arkbird_SOLG"
        date = "2022-01-06"
        reference = "https://f.hubspotusercontent30.net/hubfs/8776530/Sygnia-%20Elephant%20Beetle_Jan2022.pdf"
        hash1 = "34ab574e2ec73dbd4e0345275002852fe7397f7ab84505612b7a8f1780621388"
        hash2 = "a54b3b03910ed298fa644c495937d5fd9dfe46b8b05404440b572394c5ba5a6c"
        hash3 = "7d82a56cacebf8331f335dfbbbc76bc68033489037ae16e862bc56bf2088de77"
        hash4 = "ffc85e5a01780455adcf5762df7452d27c05da75b9162870431ebc470608b73b"
        tlp = "clear"
        adversary = "fin13"
    strings:
        $s1 = { 6e 65 77 20 50 72 6f 63 65 73 73 42 75 69 6c 64 65 72 28 20 63 6f 6d 6d 61 6e 64 20 29 3b }
        $s2 = { 70 72 6f 62 75 69 6c 64 65 72 2e 73 74 61 72 74 28 29 }
        $s3 = { 70 72 6f 63 65 73 73 2e 67 65 74 49 6e 70 75 74 53 74 72 65 61 6d 28 29 }
        $s4 = { 6e 65 77 20 49 6e 70 75 74 53 74 72 65 61 6d 52 65 61 64 65 72 }
        $x1 = { 53 74 72 69 6e 67 5b 5d 20 63 6f 6d 6d 61 6e 64 20 3d 20 7b 22 73 68 22 2c 20 22 2d 63 22 2c 20 72 65 71 75 65 73 74 2e 67 65 74 50 61 72 61 6d 65 74 65 72 28 22 [1-10] 22 29 }
        $x2 = { 53 74 72 69 6e 67 5b 5d 20 63 6f 6d 6d 61 6e 64 20 3d 20 7b ( 22 43 3a 5c 5c 77 69 6e 64 6f 77 73 5c 5c 73 79 73 74 65 6d 33 32 5c 5c 63 | 22 63 ) 6d 64 2e 65 78 65 22 2c 20 22 2f 63 22 2c 20 72 65 71 75 65 73 74 2e 67 65 74 50 61 72 61 6d 65 74 65 72 28 22 [1-10] 22 29 }
    condition:
        filesize < 5KB and all of ($s*) and 1 of ($x*)
}