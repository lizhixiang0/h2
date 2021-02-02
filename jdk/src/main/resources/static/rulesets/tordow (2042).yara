/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: _hugo_gonzalez_
    Rule name: Tordow
    Rule id: 2042
    Created at: 2016-12-20 13:48:33
    Updated at: 2016-12-20 14:03:11
    
    Rating: #0
    Total detections: 9
*/

import "androguard"

rule Tordow2
{
	meta:
		description = "This rule detects tordow v2.0"
		sample = "37ece331857dc880b55ce842a8e01a1af79046a919e028c2e4e12cf962994514"
		report = "https://blog.comodo.com/comodo-news/comodo-warns-android-users-of-tordow-v2-0-outbreak/"

	strings:
		$a = "http://5.45.70.34/error_page.php"
		$b = "http://5.45.70.34/cryptocomponent.1"

	condition:
		androguard.url("http://5.45.70.34") or ( $a and $b)
		
		
}

rule RelatedtoTordow
{
	meta:
		description = "This rule detects apps related , from same serial certificate"
		sample = "ae645ea25450cdbd19d72831a387f0c20523e6d62d201561ee59949b3806a82c"

	


	condition:
		androguard.url("http://185.117.72.17") 
		
		
}

rule SameCertificate
{
	meta:
		description = "Same certificate that first samples"
	condition:
		androguard.certificate.sha1("0B7C3BC97B6D7C228F456304F5E1B75797B7265E")
}
