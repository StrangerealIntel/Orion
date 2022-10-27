rule MAL_Zanubis_Sept_2022_1 : zanubis android banker
{
   meta:
        description = "Detect configuration on the dex class of new variants of Zanubis banker malware"
        author = "Arkbird_SOLG"
        reference = "https://blog.cyble.com/2022/09/02/zanubis-new-android-banking-trojan/"
        date = "2022-09-07"
        hash1 = "675311bc99ec432a7c4bfe39fa27903f082dac3f565244ff42157f8ce2019429"
        hash2 = "f57db447aeb108c2072f81db7905fae009bf2122001ee2ff617d8987c283f95f"
        hash3 = "f502ad28bd2d2cb9003c5bd2440f8401d723a30fc5b10a2d67130b63f4258e33"
        // dex class from 4560c27d6656bcf5f5f4d101daab3ccdd5f0edd4f5b279b66464019a7cbe9aba 
        hash4 = "3ece5fcf7a379698f76fa5cbb4b037debe3132381b3d48c48edbb6f0cf35a522"
        tlp = "Clear"
        adversary = "Unknown"
   strings:
       $x1 = { 64 65 78 0a 30 33 35 }
       $s1 = { 70 00 00 00 78 56 34 12 00 00 00 00 00 00 00 00 [2] 00 00 ?? 00 00 00 70 }
       $s2 = { 4b 45 59 5f 53 54 52 }
       $s3 = { 53 4f 43 4b 45 54 5f 53 45 52 56 45 52 }
       $s4 = { 55 52 4c 5f 49 4e 49 43 49 41 4c }
       $s5 = { 73 74 72 5f 64 65 63 72 79 70 74 }
       $s6 = { 70 72 65 66 5f 63 6f 6e 66 69 67 5f 75 72 6c 73 }
       $s7 = { 73 74 72 5f 65 6e 63 72 69 70 74 }
    condition:
        filesize > 5KB and $x1 at 0 and all of ($s*)
}
