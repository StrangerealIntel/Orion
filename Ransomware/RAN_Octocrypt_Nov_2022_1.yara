rule RAN_Octocrypt_Nov_2022_1 : octocrypt ransomware
{
   meta:
        description = "Detect the Octocypt ransomware"
        author = "Arkbird_SOLG"
        reference = "https://blog.cyble.com/2022/11/18/axlocker-octocrypt-and-alice-leading-a-new-wave-of-ransomware-campaigns/"
        date = "2022-11-21"
        hash1 = "65ad38f05ec60cabdbac516d8b0e6447951a65ca698ca2046c50758c3fd0608b"
        hash2 = "9a557b61005dded36d92a2f4dafdfe9da66506ed8e2af1c851db57d8914c4344"
        tlp = "Clear"
        adversary = "-"
   strings:
        $s1 = { 83 ec 40 48 89 6c 24 38 48 8d 6c 24 38 48 89 5c 24 30 48 8b 0d 8c 67 47 00 48 89 0c 24 48 89 44 24 08 48 89 5c 24 10 48 c7 44 24 18 00 20 00 00 48 c7 44 24 20 04 00 00 00 e8 d7 94 01 00 45 0f 57 ff 65 4c 8b 34 25 28 00 00 00 4d 8b b6 00 00 00 00 48 8b 44 24 28 48 85 c0 74 0a 48 8b 6c 24 38 48 83 c4 40 c3 48 8b 05 38 67 47 00 48 89 04 24 48 c7 44 24 08 00 00 00 00 48 8b 44 24 30 48 89 44 24 10 48 c7 44 24 18 00 20 00 00 48 c7 44 24 20 04 00 00 00 e8 7a 94 01 00 45 0f 57 ff 65 4c 8b 34 25 28 00 00 00 4d 8b }
        $s2 = { 48 83 ec 48 48 89 6c 24 40 48 8d 6c 24 40 48 89 44 24 50 48 89 5c 24 58 48 83 3d be 3d 4f 00 00 75 73 48 8b 05 dd 00 46 00 48 8d 0d 66 4a 4f 00 48 89 04 24 48 89 4c 24 08 48 c7 44 24 10 04 01 00 00 e8 af 2c 00 00 45 0f 57 ff 65 4c 8b 34 25 28 00 00 00 4d 8b b6 00 00 00 00 48 8b 44 24 18 48 85 c0 0f 84 72 01 00 00 }
        $s3 = { 83 ec 30 48 c7 c1 f4 ff ff ff 48 89 0c 24 48 8b 05 82 26 43 00 ff d0 48 89 c1 48 89 0c 24 48 8d 15 3a 69 4c 00 48 89 54 24 08 44 8d 05 56 61 4c 00 4c 89 44 24 10 4c 8d 4c 24 28 49 c7 01 00 00 00 00 4c 89 4c 24 18 48 c7 44 24 20 00 00 00 00 48 8b 05 88 25 43 00 ff d0 e8 a1 e4 ff ff }
        $s4 = { 48 48 89 6c 24 40 48 8d 6c 24 40 48 8b 0d b3 db 45 00 48 8d 15 44 b7 02 00 48 89 0c 24 44 0f 11 7c 24 08 48 89 54 24 18 48 89 44 24 20 44 0f 11 7c 24 28 e8 25 09 00 00 45 0f 57 ff 65 4c 8b 34 25 28 00 00 00 4d 8b b6 00 00 00 00 }
   condition:
        uint16(0) == 0x5A4D and filesize > 60KB and all of ($s*) 
}
