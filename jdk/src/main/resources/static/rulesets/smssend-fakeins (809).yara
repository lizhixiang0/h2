/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: SMSSend-FakeIns
    Rule id: 809
    Created at: 2015-08-31 17:26:33
    Updated at: 2015-09-27 11:16:06
    
    Rating: #0
    Total detections: 71718
*/

import "androguard"



rule smssend:fakeins
{
	meta:
		sample = "04531241e81c7d928e7bc42b049eb0b4f62ecd1a1c516051893ba1167467354c"

	condition:
		androguard.certificate.sha1("405E03DF2194D1BC0DDBFF8057F634B5C40CC2BD")
}

rule smssend2:fakeins
{
	meta:
		sample = "2edf40289ee591e658730f6d21538729e0e3e1c832ae76acf207d449cfa91979"
		sample2 = "9378c6c10454b958384e0832a45eb37b58e725528e13bee1e3efe585e18e016a"
		sample3 = "4650d0f08dc2fa69516906b44119361b3cdcab429301aa5f16c7b8bfd95069c3"

	strings:
		$a = "SHA1-Digest: flyZ6fARO6a2PCu0CLg0cZExbNo="
		$b = "<br/>9800 - 296.61 RUR"
		$c = "<br/>3352 - 90.00 RUR"
	condition:
		all of them
}
