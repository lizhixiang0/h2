/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: ExaSpy
    Rule id: 1950
    Created at: 2016-11-04 08:44:05
    Updated at: 2016-11-04 08:45:32
    
    Rating: #1
    Total detections: 19
*/

rule ExaSpySimple
{
	meta:
		description = "https://www.skycure.com/blog/exaspy-commodity-android-spyware-targeting-high-level-executives/"
		sample = "fee19f19638b0f66ba5cb32c229c4cb62e197cc10ce061666c543a7d0bdf784a"

	strings:
		$a = "andr0idservices.com" nocase

	condition:
		$a
		
}
