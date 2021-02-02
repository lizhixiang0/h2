/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: Ransom.LeakerLocker
    Rule id: 3103
    Created at: 2017-07-10 08:03:38
    Updated at: 2017-07-10 13:44:10
    
    Rating: #0
    Total detections: 3
*/

import "androguard"

rule leakerlocker
{
	meta:
		description = "https://securingtomorrow.mcafee.com/mcafee-labs/leakerlocker-mobile-ransomware-acts-without-encryption/"
		sample = "486f80edfb1dea13cde87827b14491e93c189c26830b5350e31b07c787b29387"

	strings:
		$ = "updatmaster.top/click.php?cnv_id" nocase
		$ = "goupdate.bid/click.php?cnv_id" nocase
		$ = "personal data has been deleted from our servers and your privacy is secured" nocase

	condition:
		2 of them
		
}
