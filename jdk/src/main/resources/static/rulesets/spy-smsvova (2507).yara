/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: Spy-SMSVova
    Rule id: 2507
    Created at: 2017-04-20 12:13:54
    Updated at: 2017-04-20 12:15:04
    
    Rating: #0
    Total detections: 1
*/

import "androguard"

rule wefleet
{

	strings:
		$a = "wefleet.net/smstracker/ads.php" nocase

	condition:
		$a
		
}
