/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: DontKnowWhatItIs VideoTestNoicon
    Rule id: 1621
    Created at: 2016-07-14 07:59:18
    Updated at: 2016-07-14 08:25:38
    
    Rating: #2
    Total detections: 19039
*/

import "androguard"

rule VideoTestNoicon
{
    meta:
        description = "Rule to catch APKs with app name VideoTestNoicon"
    condition:
        androguard.app_name(/VideoTestNoicon/i)
}
