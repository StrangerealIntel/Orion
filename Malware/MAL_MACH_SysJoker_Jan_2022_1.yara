rule MAL_MACH_SysJoker_Jan_2022_1
{
    meta:
        description = "Detect Mach version of SysJoker backdoor"
        author = "Arkbird_SOLG"
        date = "2022-01-11"
        reference = "https://www.intezer.com/blog/malware-analysis/new-backdoor-sysjoker/"
        hash1 = "1a9a5c797777f37463b44de2b49a7f95abca786db3977dcdac0f79da739c08ac"
        hash2 = "d0febda3a3d2d68b0374c26784198dc4309dbe4a8978e44bb7584fd832c325f0"
        hash3 = "fe99db3268e058e1204aff679e0726dc77fd45d06757a5fda9eafc6a28cfb8df"
        tlp = "Clear"
        adversary = "-"
    strings:
        $s1 = { 48 89 df e8 a7 08 00 00 48 8b 48 10 48 89 0d 04 88 00 00 0f 10 00 0f 11 05 ea 87 00 00 0f 57 c0 0f 11 00 48 c7 40 10 00 00 00 00 f6 45 c8 01 74 09 48 8b 7d d8 e8 4d 09 00 00 4c 8b 3d 36 44 00 00 48 8d 35 bf 87 00 00 4c 8d 35 18 c4 fe ff 4c 89 ff 4c 89 f2 e8 51 09 00 00 48 8d 1d be 87 00 00 48 8d 35 75 24 00 00 48 89 df e8 e7 e2 fe ff 4c 89 ff 48 89 de 4c 89 f2 e8 2d 09 00 00 48 8d 1d b2 87 00 00 4c 8d 25 17 27 00 00 48 89 df 4c 89 e6 e8 c0 e2 fe ff 4c 89 ff 48 89 de 4c 89 f2 e8 06 09 00 00 48 8d 1d a3 87 00 00 48 89 df 4c 89 e6 e8 a0 e2 fe ff 4c 89 ff 48 89 de }
        $s2 = { e8 ff 04 01 00 4c 89 ff e8 49 04 01 00 f6 85 80 fd ff ff 01 74 0c 48 8b bd 90 fd ff ff e8 e0 03 01 00 f6 85 60 fd ff ff 01 74 0c 48 8b bd 70 fd ff ff e8 cb 03 01 00 41 b6 01 e9 34 fc ff ff e8 0c }
        $s3 = { 4c 89 ff be 12 27 00 00 4c 89 f2 31 c0 e8 51 09 01 00 ba 01 00 00 00 4c 89 ff be 34 00 00 00 31 c0 e8 3d 09 01 00 ba 01 00 00 00 4c 89 ff be 40 00 00 00 31 c0 e8 29 09 01 00 ba 01 00 00 00 4c 89 ff be 51 00 00 00 31 c0 e8 15 09 01 00 48 8d 15 60 fc ff ff 4c 89 ff be 2b 4e 00 00 31 c0 e8 ff 08 01 00 48 8d 95 98 fd ff ff 4c 89 ff be 11 27 00 00 31 c0 e8 e9 08 01 00 4c 89 ff e8 db 08 01 00 89 c3 48 8d bd 98 fd ff ff e8 cb 07 01 00 48 8d bd a0 fd ff ff e8 47 3f 00 00 48 85 c0 75 21 48 8b 85 98 fd ff ff 48 8b 40 e8 48 8d 3c 28 48 81 c7 98 fd ff ff 8b 77 20 83 ce 04 e8 f9 07 01 00 85 db 0f 85 93 00 00 00 48 8d 95 04 fd ff ff c7 02 00 00 00 00 4c 89 ff be 02 00 20 00 31 c0 e8 6b 08 01 00 }
        $s4 = { 48 89 e5 48 8d 3d 23 2a 00 00 48 8d 35 14 28 00 00 48 8d 0d 22 2a 00 00 ba 77 1c 00 00 e8 4f 07 00 00 55 48 89 e5 48 8d 3d 53 2a 00 00 48 8d 35 f1 27 00 00 48 8d 0d 4d 2b 00 00 ba dc 18 00 00 e8 2c 07 00 00 55 48 89 e5 48 8d 3d 30 2a 00 00 48 8d 35 ce 27 00 00 48 8d 0d 2e 2a 00 00 ba 64 18 00 00 e8 09 07 00 00 55 48 89 e5 48 8d 3d 65 35 00 00 48 8d 35 ab 27 00 00 48 8d 0d 63 35 00 00 ba 51 1b 00 00 e8 e6 06 00 }
	condition:
       uint32(0) == 0xbebafeca and filesize > 30KB and all of ($s*) 
} 
