rule APT_MoustachedBouncer_NightClub_Aug_2023_1 : apt moustachedbouncer nightclub backdoor
{
   meta:
        description = "Detect the NightClub backdoor used by MoustachedBouncer group (implant and Dropper)"
        author = "Arkbird_SOLG"
        reference = "https://www.welivesecurity.com/en/eset-research/moustachedbouncer-espionage-against-foreign-diplomats-in-belarus/"
        date = "2023-08-10"
        hash1 = "39d534148fe7ac7f3e03da1ceeee556b2e1db9cf466f7e03c24c4f899aa0c407"
        hash2 = "ee2c61216ed691f8bf1f080fb9c7d7cfc6f370e6f5c0d493db523b48e699a2ec"
        hash3 = "25412a1a41069d7c09a0b4968bdbc818155bfa02db696ea3c34350ef50fad933"
        hash4 = "daa02008b2b7c325d6169c7dc37658f9ac19f744569a685b3f8b78e6622bfa22"
        tlp = "Clear"
        adversary = "MoustachedBouncer"
   strings:
       $s1 = { 8b 43 18 3b c7 75 05 a1 7c 41 01 10 8b 93 ac 00 00 00 50 68 ?? 4a 01 10 52 ff 15 e8 41 01 10 83 c4 0c 8b d6 8b cb e8 3a 34 00 00 3b c7 0f 85 c0 07 00 00 56 53 e8 5b 39 00 00 3b c7 0f 85 b1 07 00 00 8b 8b c0 00 00 00 3b cf 74 0f 8b 83 c4 00 00 00 2b c1 c1 f8 05 3b }
       $s2 = { 8b 93 ac 00 00 00 68 70 46 01 10 68 ?? 4a 01 10 52 ff 15 e8 41 01 10 8b bb ac 00 00 00 83 c4 0c 4f 8a 47 01 47 84 c0 75 f8 8b 15 4c 41 01 10 8b 45 e0 b9 0b 00 00 00 be ?? 4a 01 10 f3 a5 66 a5 a4 8b 12 8b 8b f0 00 00 00 c1 e0 04 52 68 ?? 48 01 10 03 c8 89 45 cc ff 15 5c 41 01 10 8b 4d dc }
       $s3 = { 09 00 00 00 be ?? 4a 01 10 f3 a5 8b bb ac 00 00 00 4f eb 03 8d 49 00 8a 47 01 47 84 c0 75 f8 b9 0b 00 00 00 be ?? 4a 01 10 f3 a5 8b 0d 4c 41 01 10 8b 11 8b 4d cc 03 8b f0 00 00 00 52 68 ?? 48 01 10 ff 15 5c 41 01 10 8b 55 dc 8d 44 10 01 8b f0 8d 9b 00 00 00 00 8a 08 }
       $s4 = { 64 a1 00 00 00 00 50 83 ec 5c 53 56 a1 00 a0 01 10 33 c4 50 8d 44 24 68 64 a3 00 00 00 00 c7 44 24 14 00 00 00 00 e8 48 28 00 00 b9 10 47 01 10 8d 5c 24 18 8b f0 e8 e8 aa ff ff 8d 44 24 18 50 8d 4c 24 34 33 db 51 89 5c 24 78 e8 63 08 00 00 83 c4 08 c6 44 24 70 02 8b }
   condition:
        uint16(0) == 0x5A4D and filesize > 40KB and all of ($s*)
}
