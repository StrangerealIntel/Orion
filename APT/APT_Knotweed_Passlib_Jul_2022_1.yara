rule APT_Knotweed_Passlib_Jul_2022_1 : passlib knotweed tool
{
   meta:
        description = "Detect the passlib tool used by the knotweed group"
        author = "Arkbird_SOLG"
        reference = "https://www.microsoft.com/security/blog/2022/07/27/untangling-knotweed-european-private-sector-offensive-actor-using-0-day-exploits/"
        date = "2022-07-28"
        hash1 = "e64bea4032cf2694e85ede1745811e7585d3580821a00ae1b9123bb3d2d442d6"
        hash2 = "-"
        tlp = "Clear"
        adversary = "Knotweed"
   strings:
        $s1 = "------------------------> Browser: %s\n" wide
        $s2 = "------------------------> Extractor: %s\n" wide
        $s3 = "=========== New Extraction Event from LEX Server [%s] ================" wide
        $s4 = "Resource: [%s] - Username: [%s] - Password: [%s]" wide
        $s5 = "%s: [%s]:[%s] (http_only:%d)" wide
        $s6 = "ATTACH %Q AS vacuum_db" ascii
   condition:
       uint16(0) == 0x5A4D and filesize > 90KB and all of ($s*)
}
