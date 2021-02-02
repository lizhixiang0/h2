/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Backdoor
    Rule id: 1765
    Created at: 2016-08-26 21:14:32
    Updated at: 2016-08-29 09:40:32
    
    Rating: #1
    Total detections: 4312
*/

import "androguard"

rule backdoor
{
	meta:
		description = "This rule detects samples with a backdoor"
		sample = "0c3bc51952c71e5bb05c35346005da3baa098faf3911b9b45c3487844de9f539"

	condition:
		androguard.url("http://sys.wksnkys7.com") 
		or androguard.url("http://sys.hdyfhpoi.com") 
		or androguard.url("http://sys.syllyq1n.com") 
		or androguard.url("http://sys.aedxdrcb.com")
		or androguard.url("http://sys.aedxdrcb.com")
}
