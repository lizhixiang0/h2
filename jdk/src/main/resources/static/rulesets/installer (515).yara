/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Installer
    Rule id: 515
    Created at: 2015-05-26 10:12:48
    Updated at: 2015-08-06 15:20:09
    
    Rating: #0
    Total detections: 5079
*/

import "androguard"

rule Installer: banker
{
	meta:
		description = "Applications with Installer as an application name"

	condition:
		androguard.package_name("Jk7H.PwcD")
}
