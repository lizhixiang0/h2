/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: MKero
    Rule id: 941
    Created at: 2015-10-21 08:06:26
    Updated at: 2016-03-16 07:43:04
    
    Rating: #0
    Total detections: 115
*/

import "androguard"

rule mkero
{
	meta:
		description = "This rule detects MKero malware family"
		sample = "a1e71e8b4f8775818db65655fb3e28666f7b19fd798360297c04cfe5c9a6b87e"
		sample2 = "136ba8af7c02e260db53817a142c86b65775510295720a2ec339e70cbbebf2d4"
		source = "http://www.hotforsecurity.com/blog/sophisticated-capcha-bypassing-malware-found-in-google-play-according-to-bitdefender-researchers-12616.html"

	strings:
		$a = "com/mk/lib/receivers/MkStart"
		$b = "com/mk/lib/MkOpen"
		$c = "com/mk/lib/MkProcess"
		$d = "com/mk/lib/MkServer"
		$e = "com/mk/lib/MkSource"
		$f = "com/mk/lib/MkPages"
		$g = "com/mk/lib/receivers/MkSms"

	condition:
		all of them
		
}

rule mkero_cert
{
	condition:
		androguard.certificate.sha1("49A6EFC6A9BA3DE7ECB265E7B4C43E454ABDA05D")
}
