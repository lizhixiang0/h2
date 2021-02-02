/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: reox
    Rule name: Marcher
    Rule id: 5215
    Created at: 2019-01-18 07:37:09
    Updated at: 2019-01-18 07:42:24
    
    Rating: #0
    Total detections: 0
*/

import "androguard"


rule marcher
{
	meta:
		description = "This rule detects Sicherheits-App Banker Trojans, also known as Marcher"
		sample = "8994b4e76ced51d34ce66f60a9a0f5bec81abbcd0e795cb05483e8ae401c6cf7"

	condition:
		androguard.package_name(/[a-z]+\.[a-z]+/) and
		androguard.app_name(/.*Sicherheits[- ]App$/) and
		androguard.filter("android.app.action.DEVICE_ADMIN_ENABLED")
}
