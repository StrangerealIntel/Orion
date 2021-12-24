rule RAN_Lorenz_Dec_2021_1 
{
   meta:
        description = "Detect Lorenz ransomware"
        author = "Arkbird_SOLG"
        reference = "Internal Research"
        date = "2021-12-22"
        hash1 = "1264b40feaa824d5ba31cef3c8a4ede230c61ef71c8a7994875deefe32bd8b3d"
        hash2 = "edc2070fd8116f1df5c8d419189331ec606d10062818c5f3de865cd0f7d6db84"
        hash3 = "a0ccb9019b90716c8ee1bc0829e0e04cf7166be2f25987abbc8987e65cef2e6f"
        hash4 = "0f863d6c906f4154da19033da1b4374d6000525031c215fb7b3880182a554185"
        tlp = "white"
        adversary = "Lorenz"
   strings:
        $s1 = { 8d 8d [3] ff e8 ?? 02 00 00 e8 [2] ff ff 8b d8 8d 85 ?? fc ff ff 68 00 01 00 00 50 68 [3] 00 ff 15 [3] 00 33 c9 [0-5] 8a 84 0d ?? fc ff ff 8d 49 01 88 84 0d ?? fd ff ff 84 c0 75 eb 8d bd ?? fd ff ff 4f [0-4] 8a 47 01 8d 7f 01 84 c0 75 f6 66 a1 [3] 00 8b f3 66 89 07 8a 03 43 84 c0 75 f9 8d bd ?? fd ff ff 2b de 4f 8a 47 01 47 84 c0 75 f8 8b cb c1 e9 02 f3 a5 8b cb 83 e1 03 f3 a4 8d 8d ?? fd ff ff 49 8a 41 01 8d 49 01 84 c0 75 f6 a1 }
        $s2 = { 81 ec e8 01 00 00 a1 [2] 50 00 33 c5 89 45 fc 8d 85 28 fe ff ff 50 68 02 02 00 00 ff 15 [2] 4c 00 85 c0 75 51 6a 40 8d 45 b8 50 ff 15 [2] 4c 00 85 c0 75 41 8d 45 b8 50 ff 15 [2] 4c 00 85 c0 74 33 0f bf 48 0a 8b 40 0c 51 ff 30 8d 85 1c fe ff ff 50 e8 [3] 00 83 c4 0c ff b5 1c fe ff ff ff 15 [2] 4c 00 8b 4d fc 33 cd e8 [3] 00 8b e5 5d c3 ff 15 [2] 4c 00 8b 4d fc 33 cd e8 [3] 00 8b }
        $s3 = "#File Error#(%d) :" ascii
        $s4 = " Data: <%s> %s" ascii
        $s5 = "%ls(%d) : %ls" wide
    condition:
        uint16(0) == 0x5A4D and filesize > 80KB and 4 of ($s*) 
}