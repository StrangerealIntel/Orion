rule RAN_ELF_AvosLocker_Jan_2022_1
{
    meta:
        description = "Detect the ELF version of AvosLocker ransomware (aka AvosLinux)"
        author = "Arkbird_SOLG"
        date = "2022-01-18"
        // Last Update  = "2022-03-20"
        reference = "https://blog.cyble.com/2022/01/17/avoslocker-ransomware-linux-version-targets-vmware-esxi-servers/"
        // new variant, few improvements
        hash1 = "d7112a1e1c68c366c05bbede9dbe782bb434231f84e5a72a724cc8345d8d9d13"
        // old from January 2021
        hash2 = "0cd7b6ea8857ce827180342a1c955e79c3336a6cf2000244e5cfd4279c5fc1b6"
        hash3 = "7c935dcd672c4854495f41008120288e8e1c144089f1f06a23bd0a0f52a544b1"
        tlp = "white"
        adversary = "RAAS"
    strings:
        $s1 = { bf [2] 4f 00 31 c0 e8 [2] ff ff bf [2] 4f 00 e8 [2] ff ff bf [3] 00 e8 [2] ff ff bf [3] 00 e8 [2] ff ff [20-26] 89 [3] ff ff [0-8] 48 83 e0 f0 48 29 c4 ?? 8d ?? 24 0f ?? 83 ?? f0  }
        $s2 = { 48 8d 54 24 0f 48 8d 35 [2] 03 00 48 89 e7 e8 [2] f3 ff bf 18 00 00 00 e8 [2] f3 ff 48 89 e6 48 89 c7 49 89 c4 e8 ac fa ff ff 48 8b 3c 24 48 83 ef 18 48 3b 3d [2] 2b 00 75 16 48 8b 15 [2] 2b 00 48 8b 35 [2] 2b 00 }
        $s3 = { bf [2] 78 00 48 83 ec 10 e8 [2] ff ff ba [2] 4f 00 be [2] 78 00 bf [2] 41 00 e8 [2] ff ff 48 8d 54 24 0f be [2] 4f 00 bf [2] 78 00 e8 [2] ff ff ba [2] 4f 00 be [2] 78 00 bf [2] 41 00 e8 [2] ff ff 48 8d 54 24 0e be [2] 4f 00 bf [2] 78 00 e8 [2] ff ff ba [2] 4f 00 be [2] 78 00 bf [2] 41 00 e8 [2] ff ff 48 8d 54 24 0d be [2] 4f 00 bf [2] 78 00 e8 [2] ff ff ba [2] 4f 00 be [2] 78 00 bf [2] 41 00 e8 [2] ff ff 48 8d 54 24 0c be [2] 4f 00 bf [2] 78 00 e8 [2] ff ff ba [2] 4f 00 be [2] 78 00 bf  [2] 41 00 e8 [2] ff ff bf [2] 78 00 e8 [2] 00 00 ba }
        $s4 = { 49 83 ?? 08 4c 3b [3] ff ff 74 [2] 8b [2] 10 48 [8-16] ff e8 [2] ff ff 48 85 c0 75 ?? 48 [1-8] 75 c0 [0-3] e8 [2] ff ff 48 85 c0 75 ?? eb }
    condition:
      uint32(0) == 0x464C457F and filesize > 90KB and all of ($s*) 
}
