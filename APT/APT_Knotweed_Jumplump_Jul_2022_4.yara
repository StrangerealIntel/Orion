rule APT_Knotweed_Jumplump_Jul_2022_4 : jumplump knotweed loader
{
   meta:
        description = "Detect the Jumplump loader used by the knotweed group"
        author = "Arkbird_SOLG"
        reference = "https://www.microsoft.com/security/blog/2022/07/27/untangling-knotweed-european-private-sector-offensive-actor-using-0-day-exploits/"
        date = "2022-07-29"
        hash1 = "7f29b69eb1af1cc6c1998bad980640bfe779525fd5bb775bc36a0ce3789a8bfc"
        hash2 = "-"
        tlp = "Clear"
        adversary = "Knotweed"
   strings:
        $s1 = "\\system32\\wbem\\wmiprvsd.dll" wide
        $s2 = "SOFTWARE\\Microsoft\\WBEM\\CIMOM\\SecuredHostProviders" wide
        //  Microsoft WBEM Log File Event Consumer Provider (COM)
        $s3 = "{266c72d4-62e8-11d1-ad89-00c04fd8fdff}" wide
        $s4 = "Provider::ExecQuery" wide
        $s5 = "root\\cimv2" wide
        // KernelTraceProvider Class (COM)
        $s6 = "{9877D8A7-FDA1-43F9-AEEA-F90747EA66B0}" wide
   condition:
       uint16(0) == 0x5A4D and filesize > 90KB and all of ($s*)
}
