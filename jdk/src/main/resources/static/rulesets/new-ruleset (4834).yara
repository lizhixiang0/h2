/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: lcepok
    Rule name: New Ruleset
    Rule id: 4834
    Created at: 2018-08-23 14:57:26
    Updated at: 2018-08-23 21:56:14
    
    Rating: #0
    Total detections: 0
*/

import "androguard"


rule bzwbk
{
	meta:
		description = "1st test yara rule for detect all bzwbk banking app"
		
	

	condition:
		
		androguard.app_name(/bzwbk/) or
		androguard.app_name(/bzwbk24/)or
		androguard.app_name(/BZWBK24/) or
		androguard.app_name(/BZWBK/)or 
		
		androguard.app_name(/bzwbk mobile/) or
		androguard.app_name(/bzwbk24 mobile/)or
		androguard.app_name(/BZWBK24 mobile/) or
		androguard.app_name(/BZWBK mobile/)or
		androguard.app_name("bzwbk*")or
		androguard.app_name(/bzwbk*/)
		
		
}
