/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: jimmy
    Rule name: Sms-fraud
    Rule id: 1996
    Created at: 2016-11-29 13:15:40
    Updated at: 2016-11-29 13:15:50
    
    Rating: #0
    Total detections: 23779
*/

import "cuckoo"

rule smsfraud
{
	meta:
		description = "This rule detects several sms fraud applications"
		sample = "ab356f0672f370b5e95383bed5a6396d87849d0396559db458a757fbdb1fe495"
		
    condition:
		cuckoo.network.dns_lookup(/waply\.ru/) or cuckoo.network.dns_lookup(/depositmobi\.com/)

}
