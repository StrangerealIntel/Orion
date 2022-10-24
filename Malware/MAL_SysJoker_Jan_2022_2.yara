rule MAL_SysJoker_Jan_2022_2
{
    meta:
        description = "Detect implant of SysJoker backdoor"
        author = "Arkbird_SOLG"
        date = "2022-01-11"
        reference = "https://www.intezer.com/blog/malware-analysis/new-backdoor-sysjoker/"
        hash1 = "1ffd6559d21470c40dcf9236da51e5823d7ad58c93502279871c3fe7718c901c"
        hash2 = "-"
        tlp = "Clear"
        adversary = "-"
        level = "Experimental"
    strings:
        $s1 = { 26 69 70 3d 00 00 00 00 26 61 6e 74 69 3d 00 00 26 6f 73 3d 00 00 00 00 26 75 73 65 72 5f 74 6f 6b 65 6e 3d [6-14] 00 00 00 26 6e 61 6d 65 3d 00 00 73 65 72 69 61 6c 3d 00 2f 61 70 69 2f 61 74 74 61 63 68 00 74 6f 6b 65 6e }
        $s2 = { 8b 01 8b 40 0c ff d0 83 c0 10 89 45 ac 68 78 70 45 00 8d 4d ac c6 45 fc 0d e8 0d ae 00 00 84 c0 75 0d 68 78 70 45 00 8d 4d ac e8 0c 95 00 00 68 1c 01 46 00 8d 55 88 c6 45 fc 0e 8d 8d 74 ff ff ff e8 15 8d 00 00 83 c4 04 8d 4d ac c6 45 fc 0f 51 8b d0 8d 8d 78 ff ff }
        $s3 = { 8b 01 8b 40 0c ff d0 83 c0 10 89 45 b4 68 48 6f 45 00 8d 4d b4 c6 45 fc 0c e8 94 b9 00 00 84 c0 75 0d 68 48 6f 45 00 8d 4d b4 e8 93 a0 00 00 68 1c 01 46 00 8d 55 90 c6 45 fc 0d 8d 4d b0 e8 9f 98 00 00 83 c4 04 8d 4d b4 c6 45 fc 0e 51 8b d0 8d 4d 80 e8 8a 98 00 00 83 c4 04 68 1c 01 46 00 8b d0 c6 45 fc 0f 8d 4d 84 e8 74 98 00 00 83 c4 04 8d 4d b8 c6 45 fc 10 }
        $s4 = { 6a 4d 33 c0 c7 45 e4 00 00 00 00 68 a8 6c 45 00 8d 4d d4 c7 45 e8 07 00 00 00 66 89 45 d4 e8 72 03 01 00 c6 45 fc 06 8d 45 d4 83 7d e8 08 8d 8d 60 ff ff ff ff 75 e4 0f 43 45 d4 50 e8 54 03 01 00 c6 45 fc 05 8b 55 e8 83 fa 08 72 32 8b 4d d4 8d 14 55 02 00 00 00 8b c1 81 fa 00 10 00 00 72 14 8b }
	condition:
       uint16(0) == 0x5A4D and filesize > 30KB and all of ($s*) 
} 
