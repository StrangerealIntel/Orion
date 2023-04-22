rule RAN_Money_Message_Mar_2023_1 : money_message ransomware
{
    meta:
        description = "Detect Money Message ransomware"
        author = "Arkbird_SOLG"
        date = "2023-03-29"
        reference = "https://twitter.com/Threatlabz/status/1641113991824158720"
        hash1 = "bbdac308d2b15a4724de7919bf8e9ffa713dea60ae3a482417c44c60012a654b"
        hash2 = "97abcf01deea74eb3771ddcef8bfc0906b46a55172588de8e2ad20f8d92b2de7"
        hash3 = "dc563953f845fb88c6375b3e9311ebed49ce4bcd613f7044989304c8de384dac"
        tlp = "Clear"
        adversary = "RAAS"
    strings:
        $s1 = /"mutex_name":\s"[0-z]{5}-[0-z]{5}-[0-z]{5}-[0-z]{5}",/
        $s2 = /"extensions":\s(\[]|\["\w+"]),/
        $s3 = /skip_directories":\s\[/
        $s4 = /"domain_password":\s\["(.)+","/
        $s5 = { 83 bd 30 ff ff ff 10 8d 85 1c ff ff ff c6 45 fc ?? 0f 43 85 1c ff ff ff 50 6a 00 6a 00 ff 15 }
    condition:
       uint16(0) == 0x5A4D and filesize > 90KB and all of ($s*) 
} 
