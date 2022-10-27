rule APT_Actor210426_loader_Aug_2022_1 : loader actor210426
{
    meta:
        description = "Detect the loader used by the Actor210426 group"
        author = "Arkbird_SOLG"
        date = "2022-08-09"
        reference = "https://twitter.com/souiten/status/1556891273910312961"
        hash1 = "aa13c3c4e80b7eb1b271ecb8c8ca7a804c0726e9008569780b600db799328b9d"
        hash2 = "7327d83e087384e79c91d4fb3e209f832d5b2d47edad1a591f407675493ecd18"
        hash3 = "4fead7f1a26f07df4180f34b099ae1474bdfd401f1e5449d89c583a73d802880"
        hash4 = "56354a1123d794c37351284bfb79045b7d92861cac0f1eed058a7fda819aaf83"
        tlp = "Clear"
        adversary = "Actor210426"
    strings:
        $s1 = { 33 c0 c7 45 08 47 00 6c 00 4c 8d 45 08 66 89 45 38 33 d2 c7 45 0c 6f 00 62 00 33 c9 c7 45 10 61 00 6c 00 c7 45 14 5c 00 55 00 c7 45 18 6e 00 69 00 c7 45 1c 76 00 65 00 c7 45 20 72 00 73 00 c7 45 24 61 00 6c 00 c7 45 28 20 00 48 00 c7 45 2c 65 00 61 00 c7 45 30 64 00 65 00 c7 45 34 72 00 73 00 ff 15 f8 1a 00 00 48 8b d8 ff 15 f7 1a 00 00 3d b7 00 00 00 75 0e 48 8b cb ff 15 f7 1a 00 00 e9 0f 01 00 00 ba 6a 00 00 00 48 8b ce 44 8d 42 a0 ff 15 f8 1a 00 00 48 8b d0 48 8b ce 48 8b d8 ff 15 e1 1a 00 00 48 8b d3 48 8b ce 48 8b f8 ff 15 8a 1a 00 00 8b c8 44 8b f0 e8 84 01 00 00 48 8b cf 48 8b f0 ff 15 a4 1a 00 00 45 8b c6 48 8b ce 48 8b d0 e8 fd 10 00 00 41 8b d6 48 8b ce e8 7b fc ff ff 66 0f 6f 05 33 1d 00 00 48 8d 55 70 49 8b cf f3 0f 7f 45 70 ff 15 99 1a 00 00 4e 8d 04 b5 00 00 00 00 b9 00 00 04 00 4b 8d 14 36 48 8b d8 ff 15 2f 1a 00 00 45 8b c6 ba 08 00 00 00 48 8b }
        $s2 = { e8 aa 00 00 00 48 8b 44 24 38 48 89 05 b2 37 00 00 48 8d 44 24 38 48 83 c0 08 48 89 05 42 37 00 00 48 8b 05 9b 37 00 00 48 89 05 0c 36 00 00 48 8b 44 24 40 48 89 05 10 37 00 00 c7 05 e6 35 00 00 09 04 00 c0 c7 05 e0 35 00 00 01 00 00 00 c7 05 ea 35 00 00 01 00 00 00 b8 08 00 00 00 48 6b c0 00 48 8d 0d e2 35 00 00 48 c7 04 01 02 00 00 00 b8 08 00 00 00 48 6b c0 00 48 8b 0d c2 34 00 00 48 89 4c 04 20 b8 08 00 00 00 48 6b c0 01 48 8b 0d a5 34 00 00 48 89 4c 04 20 48 8d 0d b1 16 00 00 e8 00 ff ff ff 48 }
        $s3 = { ba 6a 00 00 00 48 8b ce 44 8d 42 a0 ff 15 f8 1a 00 00 48 8b d0 48 8b ce 48 8b d8 ff 15 e1 1a 00 00 48 8b d3 48 8b ce 48 8b f8 ff 15 8a 1a 00 00 8b c8 44 8b f0 e8 84 01 00 00 48 8b cf 48 8b f0 ff 15 a4 1a 00 00 45 8b c6 48 8b ce 48 8b d0 e8 fd 10 00 00 41 8b d6 48 8b ce e8 7b fc ff ff 66 0f 6f 05 33 1d 00 00 48 8d 55 70 49 8b cf f3 0f 7f 45 70 ff 15 99 1a 00 00 4e 8d 04 b5 00 00 00 00 b9 00 00 04 00 4b 8d 14 36 48 8b d8 ff 15 2f 1a 00 00 45 8b c6 ba 08 00 00 00 48 8b c8 }
    condition:
         uint16(0) == 0x5A4D  and filesize > 35KB and all of ($s*)
}
