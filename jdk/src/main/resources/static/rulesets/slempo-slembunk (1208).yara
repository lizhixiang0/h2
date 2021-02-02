/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: oguzhantopgul
    Rule name: Slempo, SlemBunk
    Rule id: 1208
    Created at: 2016-02-15 13:49:52
    Updated at: 2016-02-15 13:54:02
    
    Rating: #0
    Total detections: 394
*/

import "androguard"



rule slempo : package
{
	meta:
		description = "This rule detects the slempo (slembunk) variant malwares by using package name and app name comparison"
		sample = "24c95bbafaccc6faa3813e9b7f28facba7445d64a9aa759d0a1f87aa252e8345"

	condition:
		androguard.package_name("org.slempo.service")
}
