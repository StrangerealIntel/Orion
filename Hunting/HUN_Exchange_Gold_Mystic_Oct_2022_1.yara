rule HUN_Exchange_Gold_Mystic_Oct_2022_1 : gold_mystic exchange
{
   meta:
      description = "Detect the implant used against vulnerable Exchange servers by the Gold Mystic group (Lockbit)"
      author = "Arkbird_SOLG"
      reference = "https://asec.ahnlab.com/ko/39682/"
      date = "2022-10-22"
      hash1 = "baf8397ba06ebbc8c5489f1dc417bab5abe6095efd3d992a7f4a9f02726d55b7"
      hash2 = "c597c75c6b6b283e3b5c8caeee095d60902e7396536444b59513677a94667ff8"
      tlp = "Clear"
      adversary = "Gold Mystic"
   strings:
      $s1 = /-match \"\(\?[0-z]{1,8}\)\^[0-z]{1,15}\(.\+\)[0-z]{1,15}\$\"/
      $s2 = /foreach \(\$[0-z]{1,12} in @\(\"/
      $s3 = /-\$[0-z]{1,12}.Length\] -join ''/
      $s4 = /\| % \{\$[0-z]{1,12}\+=\$_\}/
      $s5 = { 24 70 73 46 69 6c 65 3d 24 50 53 43 6f 6d 6d 61 6e 64 50 61 74 68 }
      $s6 = /iex[ ]{1,4}\$[0-z]{1,12}/
   condition:
     filesize > 100KB and all of ($s*)
}
