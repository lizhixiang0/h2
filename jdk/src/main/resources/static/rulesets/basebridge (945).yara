/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: basebridge
    Rule id: 945
    Created at: 2015-10-23 05:17:33
    Updated at: 2015-10-23 05:56:38
    
    Rating: #1
    Total detections: 1467
*/

rule basebridge
{
	meta:
		description = "A forwards confidential details to a remote server."
		sample = "7468c48d980f0255630d205728e435e299613038b53c3f3e2e4da264ceaddaf5"
		source = "https://www.f-secure.com/v-descs/trojan_android_basebridge.shtml"

	strings:
		$a = "zhangling1"

	condition:
		all of them
		
}
