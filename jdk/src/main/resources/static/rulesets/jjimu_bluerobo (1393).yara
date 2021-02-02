/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: Jjimu_Bluerobo
    Rule id: 1393
    Created at: 2016-05-13 10:38:57
    Updated at: 2016-05-13 11:21:47
    
    Rating: #1
    Total detections: 208
*/

rule ransomware
{
	meta:
		description = "This rule detects ijimu.com and bluerobo.com see source"
		sample = "c2f5175eb7a9833bbba8ee6652e9fa69a0026fb18a614f96a4910380a5960d3f"
		source = "http://www.hotforsecurity.com/blog/android-malware-promises-porn-but-roots-device-and-installs-other-malware-13900.html"

	strings:
		$a = "http://root.ijimu.com:7354/"
		$b = "http://p.bluerobo.com:7354/"
		$c = "http://p2.bluerobo.com:7354/"

	condition:
		1 of them
		
}
