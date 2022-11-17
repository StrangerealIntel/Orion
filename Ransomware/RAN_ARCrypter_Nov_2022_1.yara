rule RAN_ARCrypter_Nov_2022_1 : arcrypter ransomware
{
   meta:
        description = "Detect ARCrypter ransomware"
        author = "Arkbird_SOLG"
        reference = "https://blogs.blackberry.com/en/2022/11/arcrypter-ransomware-expands-its-operations-from-latin-america-to-the-world"
        date = "2022-11-16"
        hash1 = "e1f01b2c624f705cb34c5c1b6d84f11b1d9196c610f6f4dd801a287f3192bf76"
        hash2 = "dacce1811b69469f4fd22ca7304ab01d57f4861574d5eeb2c35c0931318582ae"
        hash3 = "39b74b2fb057e8c78a2ba6639cf3d58ae91685e6ac13b57b70d2afb158cf742d"
        tlp = "Clear"
        adversary = "-"
   strings:
        $s1 = { 72 65 67 20 61 64 64 20 22 68 6b 63 75 5c 43 6f 6e 74 72 6f 6c 20 50 61 6e 65 6c 5c 49 6e 74 65 72 6e 61 74 69 6f 6e 61 6c 22 20 2f 76 20 73 53 68 6f 72 74 44 61 74 65 20 2f 74 20 52 45 47 5f 53 5a 20 2f 64 20 22 41 4c 4c 20 59 4f 55 52 20 46 49 4c 45 53 20 48 41 53 20 42 45 45 4e 20 45 4e 43 52 59 50 54 45 44 22 20 2f 66 00 00 00 00 72 65 67 20 61 64 64 20 22 68 6b 6c 6d 5c 53 59 53 54 45 4d 5c 43 6f 6e 74 72 6f 6c 53 65 74 30 30 31 5c 43 6f 6e 74 72 6f 6c 5c 43 6f 6d 6d 6f 6e 47 6c 6f 62 55 73 65 72 53 65 74 74 69 6e 67 73 5c 43 6f 6e 74 72 6f 6c 20 50 61 6e 65 6c 5c 49 6e 74 65 72 6e 61 74 69 6f 6e 61 6c 22 20 2f 76 20 73 53 68 6f 72 74 44 61 74 65 20 2f 74 20 52 45 47 5f 53 5a 20 2f 64 20 22 41 4c 4c 20 59 4f 55 52 20 46 49 4c 45 53 20 48 41 53 20 42 45 45 4e 20 45 4e 43 52 59 50 54 45 44 22 20 2f 66 }
        $s2 = { 7c 7c 20 53 54 41 52 54 20 22 22 20 22 00 00 54 41 53 4b 4c 49 53 54 20 7c 3e 4e 55 4c 20 46 49 4e 44 53 54 52 20 2f 42 20 2f 4c 20 2f 49 20 2f 43 3a 00 00 00 00 00 54 49 4d 45 4f 55 54 20 2f 54 20 31 20 2f 4e 4f 42 52 45 41 4b 3e 4e 55 4c }
        $s3 = { 65 78 70 6c 6f 72 65 72 2e 65 78 65 20 2e 5c 72 65 61 64 6d 65 5f 66 6f 72 5f 75 6e 6c 6f 63 6b 2e 74 78 74 }
   condition:
        uint16(0) == 0x5A4D and filesize > 60KB and all of ($s*) 
}
