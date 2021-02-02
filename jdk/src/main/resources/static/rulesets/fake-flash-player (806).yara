/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: ldelosieres
    Rule name: Fake Flash player
    Rule id: 806
    Created at: 2015-08-29 18:22:07
    Updated at: 2015-08-29 18:27:01
    
    Rating: #0
    Total detections: 24647
*/

import "androguard"

rule FakeFlashPlayer
{
	meta:
		description = "Fake FlashPlayer apps"
	condition:
		androguard.app_name("Flash Player") or
		androguard.app_name("FlashPlayer") or
		androguard.app_name("Flash_Player") or
		androguard.app_name("Flash update")
}
