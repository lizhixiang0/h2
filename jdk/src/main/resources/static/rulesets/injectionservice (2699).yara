/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: InjectionService
    Rule id: 2699
    Created at: 2017-05-16 21:54:25
    Updated at: 2017-05-19 17:48:03
    
    Rating: #0
    Total detections: 437
*/

import "androguard"
import "file"
import "cuckoo"


rule InjectionService
{
	meta:
		description = "This rule detects samples with possible malicious injection service"
		sample = "711f83ad0772ea2360eb77ae87b3bc45"

	
	condition:
		androguard.service(/injectionService/)
		
		
}
