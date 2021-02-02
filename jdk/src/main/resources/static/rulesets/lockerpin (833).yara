/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: LockerPin
    Rule id: 833
    Created at: 2015-09-18 06:11:09
    Updated at: 2015-09-18 06:20:57
    
    Rating: #0
    Total detections: 10
*/

rule lockerpin
{
	meta:
		description = "This rule detects LockerPin apps"
		sample = "2440497f69ec5978b03ea5eaf53a63f5218439a6e85675811c990aa7104d6f72"
		sample2 = "99366d0bd705e411098fade5a221a70863038f61344a9f75f823c305aa165fb1"
		sample3 = "ca6ec46ee9435a4745fd3a03267f051dc64540dd348f127bb33e9675dadd3d52"

	strings:
		$a = "res/drawable-hdpi-v4/fbi.png"
		$b = "<b>IMEI:</b>"
		$c = "res/drawable-xhdpi-v4/hitler_inactive.png"
		$d = "res/drawable-xhdpi-v4/gov_active.pngPK"

	condition:
		all of them
		
}
