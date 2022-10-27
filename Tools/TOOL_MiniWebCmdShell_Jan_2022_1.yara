rule TOOL_MiniWebCmdShell_Jan_2022_1 : tool webshell fin13
{
    meta:
        description = "Detect a remote webshell used by the fin13 group"
        // -> https://github.com/SecWiki/WebShell-2/blob/master/Php/ava%20Server%20Faces%20MiniWebCmdShell%200.2%20by%20HeartLESS.php
        author = "Arkbird_SOLG"
        date = "2022-01-07"
        reference = "https://f.hubspotusercontent30.net/hubfs/8776530/Sygnia-%20Elephant%20Beetle_Jan2022.pdf"
        hash1 = "a73f75ab7a2408f490c721c233583316bd3eb901bd32f2a0bf04282fa6a4219c"
        tlp = "Clear"
        adversary = "fin13"
    strings:
        $s1 = { 3c 66 6f 72 6d 20 6f 6e 73 75 62 6d 69 74 3d 22 72 65 74 75 72 6e 20 73 74 61 72 74 4d 61 67 69 63 28 29 22 3e }
        $s2 = { 72 65 71 75 65 73 74 2e 67 65 74 50 61 72 61 6d 65 74 65 72 28 27 63 6d 64 27 29 }
        $s3 = { 77 69 6e 64 6f 77 2e 58 4d 4c 48 74 74 70 52 65 71 75 65 73 74 }
        $s4 = { 22 47 45 54 22 2c 6c 6f 63 61 74 69 6f 6e 2e 70 61 74 68 6e 61 6d 65 2b 22 3f 63 6d 64 3d 22 }
        $s5 = { 78 6d 6c 68 74 74 70 2e 73 65 6e 64 28 29 }
        $s6 = { 4a 61 76 61 20 53 65 72 76 65 72 20 46 61 63 65 73 20 4d 69 6e 69 57 65 62 43 6d 64 53 68 65 6c 6c }     
    condition:
        filesize < 10KB and all of ($s*) 
}
