rule MAL_Daxin_Feb_2022_2 : rootkit daxin x32 core
{
   meta:
        description = "Detect the Daxin rootkit"
        author = "Arkbird_SOLG"
        reference = "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/daxin-backdoor-espionage"
        date = "2022-03-02"
        hash1 = "81c7bb39100d358f8286da5e9aa838606c98dfcc263e9a82ed91cd438cb130d1"
        tlp = "Clear"
        adversary = "Chinese espionage APT"
   strings:
        $s1 = "\\registry\\machine\\system\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\" wide
        $s2 = { ( 5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 | 5c 00 44 00 65 00 76 00 69 00 63 00 65 00 ) 5c 00 54 00 63 00 70 00 34 }
        $s3 = { 5c 00 3f 00 3f 00 5c 00 70 00 69 00 70 00 65 00 5c 00 ( 72 00 74 00 6f 00 73 00 76 00 63 | 72 00 74 00 69 00 73 00 76 00 63 ) }
        $s4 = { 53 65 74 2d 43 6f 6f 6b 69 65 3a 20 68 74 70 6d 67 63 69 64 3d 25 73 }
    condition:
    // move to "all of them" for hunting x86 version of Daxin ($s4 ref)
        uint16(0) == 0x5A4D and filesize > 25KB and 3 of ($s*) 
}
