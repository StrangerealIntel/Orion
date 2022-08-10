rule APT_Knotweed_Mex_Jul_2022_1 : mex knotweed toolkit
{
   meta:
        description = "Detect the mex toolkit used by the knotweed group"
        author = "Arkbird_SOLG"
        reference = "https://www.microsoft.com/security/blog/2022/07/27/untangling-knotweed-european-private-sector-offensive-actor-using-0-day-exploits/"
        date = "2022-07-28"
        hash1 = "fa30be45c5c5a8f679b42ae85410f6099f66fe2b38eb7aa460bcc022babb41ca"
        hash2 = "-"
        tlp = "Clear"
        adversary = "Knotweed"
   strings:
        $s1 = "mex.exe -mep sharphound -mec -arg1 -arg2 data2" wide
        $s2 = "System32\\" wide
        $s3 = "mex.exe -mep list_plugins" wide
        $s4 = "list_plugins" wide
        $s5 = "mexecatz" wide 
   condition:
       uint16(0) == 0x5A4D and filesize > 90KB and all of ($s*)
}
