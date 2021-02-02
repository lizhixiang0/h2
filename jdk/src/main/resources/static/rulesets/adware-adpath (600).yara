/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: framirez
    Rule name: Adware adpath
    Rule id: 600
    Created at: 2015-06-17 10:13:05
    Updated at: 2015-08-06 15:20:18
    
    Rating: #0
    Total detections: 27092
*/

rule adware : ads
{
	meta:
		description = "Adware"
		sample = "5a331231f997decca388ba2d73b7dec1554e966a0795b0cb8447a336bdafd71b"

	strings:
		$string_a = "banner_layout"
		$string_b = "activity_adpath_sms"
		$string_c = "adpath_title_one"
		$string_d = "7291-2ec9362bd699d0cd6f53a5ca6cd"

	condition:
		all of ($string_*)
		
}
