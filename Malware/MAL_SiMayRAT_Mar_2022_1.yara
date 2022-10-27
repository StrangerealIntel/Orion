rule MAL_SiMayRAT_Mar_2022_1 : rat simayrat
{
   meta:
        description = "Detect a variant of SiMayRAT"
        author = "Arkbird_SOLG"
        reference = "https://twitter.com/struppigel/status/1513811422148538369"
        date = "2022-04-24"
        hash1 = "41e571339b44a1f4178a9506595ca15b0b38494bf77487f4243c815fd27b7516"
        hash2 = "09a1d00d4d99f1c30377a5e83f40f78404b9b3f466aef19d6997dbb3ad895b63"
        hash3 = "209e00af0197f32a6b8762be5d862e18ba116bd69795bca18a102fef6ff53d04"
        tlp = "Clear"
        adversary = "-"
   strings:
        $s1 = { c6 45 fc 04 e8 [3] ff 83 c4 ?? 89 85 [2] ff ff c6 45 fc 06 6a 00 8d [3-5] ff ff }
        $s2 = { 83 c4 08 c6 45 fc 01 8d [7-10] 00 8d [3] e8 [3] ff 83 c4 0c c6 45 fc 02 [0-2] 6a 00 68 [3] 00 ff 15 }
        $s3 = { c7 85 [2] ff ff [3] 00 8b 85 [2] ff ff 50 8d 8d [2] ff ff e8 [3] ff 50 e8 [3] ff 83 c4 08 }
        $s4 = { 83 c4 08 c6 45 fc ?? 68 [3] 00 8d 85 [2] ff ff 50 8d 8d [2] ff ff 51 e8 [3] ff 83 c4 0c 89 85 [2] ff ff 8b 95 [2] ff ff 89 95 [2] ff ff c6 45 fc ?? 8b 85 [2] ff ff 50 8d 8d e8 }
    condition:
        uint16(0) == 0x5A4D and filesize > 30KB and all of ($s*) 
}
