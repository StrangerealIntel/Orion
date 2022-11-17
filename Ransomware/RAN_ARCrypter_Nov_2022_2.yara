rule RAN_ARCrypter_Nov_2022_2 : arcrypter ransomware dropper
{
   meta:
        description = "Detect the dropper of ARCrypter ransomware"
        author = "Arkbird_SOLG"
        reference = "https://blogs.blackberry.com/en/2022/11/arcrypter-ransomware-expands-its-operations-from-latin-america-to-the-world"
        date = "2022-11-16"
        hash1 = "e1f01b2c624f705cb34c5c1b6d84f11b1d9196c610f6f4dd801a287f3192bf76"
        hash2 = "dacce1811b69469f4fd22ca7304ab01d57f4861574d5eeb2c35c0931318582ae"
        hash3 = "39b74b2fb057e8c78a2ba6639cf3d58ae91685e6ac13b57b70d2afb158cf742d"
        tlp = "Clear"
        adversary = "-"
   strings:
        $s1 = { 48 89 58 08 48 89 70 10 48 89 78 20 44 89 40 18 55 41 54 41 55 41 56 41 57 48 8d 68 88 48 81 ec 50 01 00 00 48 8b 05 [2] 04 00 4c 8b fa 33 d2 4d 8b f1 48 8b d9 48 89 55 88 89 55 90 88 54 24 21 38 10 0f 84 c3 07 00 00 80 38 24 44 8b ad a0 00 00 00 75 34 45 8b cd 4c 8d 44 24 21 48 8d 95 }
        $s2 = { 48 8b 03 49 8b ce 48 2b 43 08 83 e1 3f 48 99 49 8b de 48 2b c2 48 c1 fb 06 48 d1 f8 4d 8b cf 4c 8d 24 c9 48 8b f0 48 8d 05 [2] fb ff 45 33 c0 48 8b 94 d8 00 ?? 08 00 41 8b ce 4a 8b 54 e2 30 e8 b8 0e 00 00 4c 8b e8 48 8d 05 [2] fb ff 48 8b 8c d8 00 ?? 08 00 4e 3b 6c e1 30 0f 85 a2 00 00 00 4a 8b 4c e1 28 4c 8d 4c 24 30 41 b8 00 10 00 00 48 89 7c 24 20 48 8d 54 24 40 ff 15 [2] 01 00 85 }
        $s3 = { ( 40 65 63 68 6f 20 6f 66 66 0a 00 00 0a 00 00 00 74 61 73 6b 6b 69 6c 6c 20 2f 46 20 2f 49 4d | 54 49 4d 45 4f 55 54 20 2f 54 20 31 20 2f 4e 4f 42 52 45 41 4b 3e 4e 55 4c ) }
   condition:
        uint16(0) == 0x5A4D and filesize > 60KB and all of ($s*) 
}
