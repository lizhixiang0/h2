/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Mapin dropper
    Rule id: 859
    Created at: 2015-09-25 14:33:27
    Updated at: 2015-09-25 14:35:07
    
    Rating: #1
    Total detections: 68
*/

rule dropperMapin
{
	meta:
		description = "This rule detects mapin dropper files"
		sample = "7e97b234a5f169e41a2d6d35fadc786f26d35d7ca60ab646fff947a294138768"
		sample2 = "bfd13f624446a2ce8dec9006a16ae2737effbc4e79249fd3d8ea2dc1ec809f1a"

	strings:
		$a = ":Write APK file (from txt in assets) to SDCard sucessfully!"
		$b = "4Write APK (from Txt in assets) file to SDCard  Fail!"
		$c = "device_admin"

	condition:
		all of them
}
