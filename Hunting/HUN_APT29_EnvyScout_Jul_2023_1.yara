rule HUN_APT29_EnvyScout_Jul_2023_1 : envyscout apt29 hunting
{
   meta:
        description = "Hunting rule for detect possible Envyscout malware used by the APT29 group by patterns already used in the past"
        author = "Arkbird_SOLG"
        reference1 = "https://twitter.com/malwrhunterteam/status/1677023534294487049"
        reference2 = "https://twitter.com/StopMalvertisin/status/1677192614985228288"      
        date = "2023-07-07"
        hash1 = "4875a9c4af3044db281c5dc02e5386c77f331e3b92e5ae79ff9961d8cd1f7c4f"
        tlp = "Clear"
        adversary = "APT29"
   strings:
        // tags used as initial vector
        $tag1 = "<svg" ascii
        $tag2 = "<?xml" ascii 
        $tag3 = "<script" ascii
        $tag4 = "<![CDATA[" ascii
        // save format
        $m1 = "application/octet-stream" ascii
        $m2 = "application/x-cd-image" ascii
        // needed method for manipulating objects
        $st1 =  /(\w+).createObjectURL\(/
        $st2 =  /(\w+).revokeObjectURL\(/
        // Save and write the object on the disk
        $s1 = "window.location.assign(" ascii
        $s2 = "navigator.msSaveOrOpenBlob(" ascii
   condition:
     // push all of ($tag*) if you want check only SVG vector else check all the already seen initial vectors of HMTL Smugging
     1 of ($tag*) and 1 of ($m*) and filesize > 50KB and all of ($st*) and 1 of ($s*)
}
