/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Jacob
    Rule name: SandroRat
    Rule id: 1414
    Created at: 2016-05-21 13:59:42
    Updated at: 2016-05-21 14:22:18
    
    Rating: #0
    Total detections: 9942
*/

import "androguard"


rule SandroRat
{
	meta:
		author = "Jacob Soo Lead Re"
		date = "21-May-2016"
		description = "This rule detects SandroRat"
		source = "https://blogs.mcafee.com/mcafee-labs/sandrorat-android-rat-targeting-polish-banking-users-via-e-mail-phishing/"

	condition:
		androguard.activity(/net.droidjack.server/i) 
}
