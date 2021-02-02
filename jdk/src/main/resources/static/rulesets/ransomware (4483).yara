/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: r0ny
    Rule name: Ransomware
    Rule id: 4483
    Created at: 2018-05-30 05:45:57
    Updated at: 2018-05-30 05:46:07
    
    Rating: #0
    Total detections: 12
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
