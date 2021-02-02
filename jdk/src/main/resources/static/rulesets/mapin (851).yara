/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Mapin
    Rule id: 851
    Created at: 2015-09-23 06:58:59
    Updated at: 2015-09-25 14:11:05
    
    Rating: #2
    Total detections: 61
*/

rule Mapin:trojan
{
	meta:
		description = "Mapin trojan, not droppers"
		sample = "7f208d0acee62712f3fa04b0c2744c671b3a49781959aaf6f72c2c6672d53776"

	strings:
		$a = "138675150963" //GCM id
		$b = "res/xml/device_admin.xml"
		$c = "Device registered: regId ="
		

	condition:
		all of them
		
}
