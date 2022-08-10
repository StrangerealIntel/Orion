rule RAN_SafeSound_Jul_2022_1 : safeSound ransomware
{
    meta:
        description = "Detect SafeSound ransomware"
        author = "Arkbird_SOLG"
        date = "2022-07-08"
        reference = "https://bbs.kafan.cn/thread-2238731-1-1.html"
        hash1 = "8f62d06bbcc5c2ef2db32f0079903759ed296b80ed6d2795abdf730346f05fde"
        hash2 = "90ed51fea616dedcb23c6dbd131f6f216ec507c0399c8aae4ee55c4501f77270"
        hash3 = "0a82b37e1a7cb6d8e8379796e929774b30fd93a7438782df2bd6b66cad0626a2"
        tlp = "white"
        adversary = "-"
    strings:
        $s1 = "\\SafeSound.hash" ascii
        $s2 = "%SystemRoot%\\System32\\svchost.exe -k" ascii
        $s3 = "\\Key.data" ascii
        $s4 = "SYSTEM\\CurrentControlSet\\Services\\" ascii
        $s5 = "Service Stop ServiceWorkerThread ...." ascii
    condition:
       uint16(0) == 0x5A4D and filesize > 90KB and all of ($s*) 
} 
