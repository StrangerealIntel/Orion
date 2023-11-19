rule RAN_Qilim_Nov_2023_1 : qilim ransomware
{
    meta:
        description = "Detect both versions of Qilim ransomware (ELF+Win)"
        author = "Arkbird_SOLG"
        date = "2023-11-18"
        reference = "https://twitter.com/cyb3rops/status/1725849024731771022"
        // ELF version
        hash1 = "555964b2fed3cced4c75a383dd4b3cf02776dae224f4848dcc03510b1de4dbf4"
        hash2 = "0629cd5e187174cb69f3489675f8c84cc0236f11f200be384ed6c1a9aa1ce7a1"
        // Win version
        hash3 = "ee24110ddb4121b31561f86692650b63215a93fb2357b2bd3301fabc419290a3"
        tlp = "Clear"
        adversary = "Qilim"
    strings:
        $s1 = { 2d 2d 20 51 69 6c 69 6e 20 [0-3] 0a 59 6f 75 72 20 6e 65 74 77 6f 72 6b 2f 73 79 73 74 65 6d 20 77 61 73 20 65 6e 63 72 79 70 74 65 64 2e 20 [0-2] 45 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 20 68 61 76 65 20 6e 65 77 20 65 78 74 65 6e 73 69 6f 6e 2e 20 [2-4] 2d 2d 20 43 6f 6d 70 72 6f 6d 69 73 69 6e 67 20 61 6e 64 20 73 65 6e 73 69 74 69 76 65 20 64 61 74 61 }
        $s2 = { ( 25 73 5f | 52 45 41 44 4d 45 2d ) 52 45 43 4f 56 45 52 [0-1] 2e 74 78 74 }
        // For Win version
        $x1 = { 2f 76 6d 66 73 2f 76 6f 6c 75 6d 65 73 2f 5b 49 4e 46 4f 7c 53 50 52 45 41 44 5d 20 56 65 72 69 66 79 69 6e 67 20 73 75 70 70 6c 69 65 64 20 64 61 74 61 }
        $x2 = { 24 65 73 78 63 6c 69 20 3d 20 47 65 74 2d 45 73 78 43 6c 69 20 2d 56 4d 48 6f 73 74 20 24 65 73 78 69 48 6f 73 74 20 2d 56 32 20 2d 45 72 72 6f 72 41 63 74 69 6f 6e 20 53 74 6f 70 }
        // For ELF version
        $x3 = { 65 73 78 63 6c 69 20 76 6d 20 70 72 6f 63 65 73 73 20 6b 69 6c 6c 20 2d 74 20 66 6f 72 63 65 20 2d 77 20 25 6c 6c 75 00 }
        $x4 = { 65 73 78 63 6c 69 20 76 6d 20 70 72 6f 63 65 73 73 20 6b 69 6c 6c 20 2d 74 20 66 6f 72 63 65 20 2d 77 20 25 6c 6c 75 }
    condition:
       (uint32(0) == 0x464C457F or uint16(0) == 0x5A4D) and filesize > 900KB and all of ($s*) and 2 of ($x*)
}
