/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Dcarrion
    Rule name: Banker
    Rule id: 1313
    Created at: 2016-03-24 12:17:30
    Updated at: 2016-03-24 12:18:52
    
    Rating: #0
    Total detections: 0
*/

import "androguard"
import "file"
import "cuckoo"


rule silent_banker : banker
{
    meta:
        description = "This is just an example"
        thread_level = 3
        in_the_wild = true

    strings:
        $a = {6A 40 68 00 30 00 00 6A 14 8D 91}
        $b = {8D 4D B0 2B C1 83 C0 27 99 6A 4E 59 F7 F9}
        $c = "UVODFRYSIHLNWPEJXQZAKCBGMT"

    condition:
        $a or $b or $c
}
