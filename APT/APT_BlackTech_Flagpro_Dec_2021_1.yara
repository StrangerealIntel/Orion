rule APT_BlackTech_Flagpro_Dec_2021_1
{
    meta:
        description = "Detect Flagpro implant used by BlackTech group"
        author = "Arkbird_SOLG"
        reference = "https://insight-jp.nttsecurity.com/post/102hf3q/flagpro-the-new-malware-used-by-blacktech"
        hash1 = "54e6ea47eb04634d3e87fd7787e2136ccfbcc80ade34f246a12cf93bab527f6b"
        hash2 = "77680fb906476f0d84e15d5032f09108fdef8933bcad0b941c9f375fedd0b2c9"
        hash3 = "e81255ff6e0ed937603748c1442ce9d6588decf6922537037cf3f1a7369a8876"
        hash4 = "bd431a53c65170dee9ff174ea2865b49edf395023bd5d69f61150d83babba52d"
        date = "2021-12-30"
        tlp = "Clear"
        adversary = "BlackTech"
    strings:
        $s1 = { 8d 44 24 10 50 8d 4c 24 18 51 6a 00 8d 94 24 3c 0c 00 00 6a 00 89 54 24 2c c7 44 24 28 4a 00 00 00 ff 15 [3] 00 85 c0 0f 84 [2] 00 00 33 db 39 5c 24 14 0f 86 [2] 00 00 8b }
        $s2 = { 64 a1 00 00 00 00 50 81 ec 98 04 00 00 a1 [3] 00 33 c4 89 84 24 94 04 00 00 53 55 57 a1 [3] 00 33 c4 50 8d 84 24 a8 04 00 00 64 a3 00 00 00 00 33 db 53 8d 44 24 24 }
        $s3 = { 8d ?? 24 ?? 03 00 00 ?? 68 04 01 00 00 }
        $s4 = "~MYTEMP" wide
        $s5 = { 6a 40 8d 44 24 ?? 53 50 c7 44 24 ?? 44 00 00 00 e8 [3] 00 83 c4 0c 8d 4c 24 ?? 51 ff 15 [3] 00 8b 44 24 1c 89 44 24 ?? 89 44 24 ?? 8d 44 24 ?? 50 8d 4c 24 ?? 51 53 53 53 6a 01 53 53 [13] 00 00 }
    condition:
        uint16(0) == 0x5A4D and filesize > 200KB and all of ($s*) 
}
