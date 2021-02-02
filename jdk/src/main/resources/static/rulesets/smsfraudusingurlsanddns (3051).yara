/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: Sarcares
    Rule name: SmsFraudUsingURLsAndDNS
    Rule id: 3051
    Created at: 2017-06-27 11:42:00
    Updated at: 2017-06-30 17:30:23
    
    Rating: #0
    Total detections: 4380
*/

import "androguard"
import "cuckoo"

rule SmsFraudUsingURLsAndDNS : smsfraud
{
	meta:
		description = "This rule should match applications that send SMS"
		inspired_by = "https://koodous.com/rulesets/3047"

	condition:
		androguard.url("app.tbjyz.com")
		or androguard.url("tools.zhxapp.com")
		or cuckoo.network.dns_lookup(/app\.tbjyz\.com/)
		or cuckoo.network.dns_lookup(/tools\.zhxapp\.com/)
}
