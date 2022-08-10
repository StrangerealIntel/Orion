rule TOOL_JspFileBrowser_Jan_2022_1 : tool fin13
{
    meta:
        description = "Detect a legitimate tool that allows remote web-based file access and manipulation used by the fin13 group"
        // -> https://www.vonloesch.de/filebrowser.html
        author = "Arkbird_SOLG"
        date = "2022-01-07"
        reference = "https://f.hubspotusercontent30.net/hubfs/8776530/Sygnia-%20Elephant%20Beetle_Jan2022.pdf"
        hash1 = "cc07921318364e6f3258c3653c8b8c066f252c7c90a6c0e245890f96c2ec61b8"
        tlp = "clear"
        adversary = "fin13"
    strings:
        $s1 = { 20 28 69 73 50 61 63 6b 65 64 28 6e 61 6d 65 2c 20 74 72 75 65 29 29 20 65 6c 69 6e 6b 20 3d 20 61 68 72 65 66 20 2b 20 22 75 6e 70 61 63 6b 66 69 6c 65 3d 22 }
        $s2 = { 6e 61 6d 65 3d 22 53 75 62 6d 69 74 22 20 76 61 6c 75 65 3d 22 3c 25 3d 53 41 56 45 5f 41 53 5f 5a 49 50 25 3e 22 3e }
        $s3 = { 76 61 6c 75 65 3d 22 3c 25 3d 55 50 4c 4f 41 44 5f 46 49 4c 45 53 25 3e 22 0a 09 09 6f 6e 43 6c 69 63 6b 3d 22 6a 61 76 61 73 63 72 69 70 74 3a 70 6f 70 55 70 28 27 3c 25 3d 20 62 72 6f 77 73 65 72 5f 6e 61 6d 65 25 3e 27 29 }
        $s4 = { 6e 61 6d 65 3d 22 53 75 62 6d 69 74 22 20 76 61 6c 75 65 3d 22 3c 25 3d 4c 41 55 4e 43 48 5f 43 4f 4d 4d 41 4e 44 25 3e 22 }
        $s5 = { 65 6e 74 72 79 5b 69 5d 2e 67 65 74 41 62 73 6f 6c 75 74 65 50 61 74 68 28 29 2e 74 6f 4c 6f 77 65 72 43 61 73 65 28 29 2e 65 71 75 61 6c 73 28 46 4f 52 42 49 44 44 45 4e 5f 44 52 49 56 45 53 5b 69 32 5d 29 }
        $s6 = { 6a 73 70 20 46 69 6c 65 20 42 72 6f 77 73 65 72 20 76 65 72 73 69 6f 6e 20 3c 25 3d 20 56 45 52 53 49 4f 4e 5f 4e 52 25 3e }
    condition:
        filesize > 5KB and all of ($s*) 
}
