rule RAN_ELF_AvosLocker_Jan_2022_1
{
    meta:
        description = "Detect the ELF version of AvosLocker ransomware (aka AvosLinux)"
        author = "Arkbird_SOLG"
        date = "2022-01-18"
        reference = "https://blog.cyble.com/2022/01/17/avoslocker-ransomware-linux-version-targets-vmware-esxi-servers/"
        hash1 = "10ab76cd6d6b50d26fde5fe54e8d80fceeb744de8dbafddff470939fac6a98c4"
        hash2 = "0cd7b6ea8857ce827180342a1c955e79c3336a6cf2000244e5cfd4279c5fc1b6"
        hash3 = "7c935dcd672c4854495f41008120288e8e1c144089f1f06a23bd0a0f52a544b1"
        tlp = "white"
        adversary = "RAAS"
    strings:
        $s1 = { bf ?? 5a 4f 00 31 c0 e8 [2] ff ff bf [2] 4f 00 e8 [2] ff ff bf 05 00 00 00 e8 [2] ff ff bf ?? 5a 4f 00 e8 [2] ff ff [20-24] 89 ?? 90 ef ff ff [3-5] 00 00 00 48 83 e0 f0 48 29 c4 48 8d 54 24 0f 48 83 e2 f0 48 89 95 98 ef ff ff eb [1-5] 48 8d 7d a0 48 ?? 2f 76 6d 66 73 2f 76 6f c7 45 a8 6c 75 6d 65 48 89 ?? a0 66 c7 45 ac 73 2f c6 45 ae 00 e8 [2] ff ff }
        $s2 = { 48 8d 54 24 0f 48 8d 35 ?? 6c 03 00 48 89 e7 e8 ?? c3 f3 ff bf 18 00 00 00 e8 ?? c0 f3 ff 48 89 e6 48 89 c7 49 89 c4 e8 ac fa ff ff 48 8b 3c 24 48 83 ef 18 48 3b 3d [2] 2b 00 75 16 48 8b 15 [2] 2b 00 48 8b 35 [2] 2b 00 }
        $s3 = { bf ?? b9 78 00 48 83 ec 10 e8 ?? b9 ff ff ba [2] 4f 00 be ?? b9 78 00 bf [2] 41 00 e8 [2] ff ff 48 8d 54 24 0f be [2] 4f 00 bf e0 b2 78 00 e8 [2] ff ff ba [2] 4f 00 be e0 b2 78 00 bf [2] 41 00 e8 [2] ff ff 48 8d 54 24 0e be [2] 4f 00 bf e8 b2 78 00 e8 [2] ff ff ba [2] 4f 00 be e8 b2 78 00 bf [2] 41 00 e8 [2] ff ff 48 8d 54 24 0d be [2] 4f 00 bf f0 b2 78 00 e8 [2] ff ff ba [2] 4f 00 be f0 b2 78 00 bf [2] 41 00 e8 [2] ff ff 48 8d 54 24 0c be [2] 4f 00 bf f8 b2 78 00 e8 [2] ff ff ba [2] 4f 00 be f8 b2 78 00 bf [2] 41 00 e8 [2] ff ff bf 00 b3 78 00 e8 ?? 3b 00 00 ba }
        $s4 = { 0f 1f 44 00 00 48 89 e6 bf ?? 58 4f 00 31 c0 e8 [2] ff ff 48 89 ea be 0b 04 00 00 48 89 e7 e8 [2] ff ff 48 85 c0 75 dc 48 89 ef e8 [2] ff ff 48 81 c4 18 04 00 00 5b 5d c3 bf ?? 58 4f 00 e8 ?? fb ff ff bf 01 00 00 00 e8 ?? f9 ff ff 66 66 66 66 66 }
    condition:
      uint32(0) == 0x464C457F and filesize > 90KB and all of ($s*) 
}
