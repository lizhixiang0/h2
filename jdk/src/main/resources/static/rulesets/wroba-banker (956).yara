/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: framirez
    Rule name: Wroba Banker
    Rule id: 956
    Created at: 2015-10-30 11:58:18
    Updated at: 2015-11-24 13:39:29
    
    Rating: #0
    Total detections: 585
*/

import "androguard"

rule banker_ip_control : banker candc
{
	meta:
		description = "g = string = properties.getProperty('xmpp', '126.5.122.217');"
	strings:
		$ip = "xmpp=126.5.122.217"
		$brc = "net.piao.mobile.MYBROADCAST"
	condition:
		any of them
}

rule banker_cromosome
{
	meta: 
		description = "get strings for cromosome.py use a lot of samples"
	strings:
		$string_a = "http://impl.service.server.phonemanager.org"
		$string_b = "http://%1$s/PhoneManager/services/BankWebService?wsdl"
		$string_c = "(init system configuration args.........."
		$string_d = "parse phoneLog json data error!!!!"
		
	condition:
		($string_a or $string_b) and any of ($string_c, $string_d)
		
}

rule banker_cert : cert
{
	meta:
		description = "This rule detects by banker certificates. Valid certificate A828FB8872A1127B131232F00B46B6DA05DEAF51"
		sample = "e6ef34577a75fc0dc0a1f473304de1fc3a0d7d330bf58448db5f3108ed92741b"

	condition:
		androguard.certificate.sha1("1D20151ACC7D0F32F4054C4BE9559129512C2A52") or
		androguard.certificate.sha1("FF8F43BB67FADCD49BA75DDC29523EF10301B0C5") or
		androguard.certificate.sha1("B5A8D5C64BD67D0BDD7937A09F70325A99EB9EFA") or
		androguard.certificate.sha1("3196E8E65F55B44B5C9414C2BC3B8CBCBEEF9467") or
		androguard.certificate.sha1("C0A4F86CF0012139BBB9728001C3B011B468F268") or
		androguard.certificate.sha1("7D7B5AB62AE9249C2F1BE8D2815B99FFC0D53749") or
		androguard.certificate.sha1("8527B91FE37B33FEC02E6F3E176C63A425A799C6") or
		androguard.certificate.sha1("0F1CA787A6F5760CF7D74CEB7475AD1BC83ADECC") or
		androguard.certificate.sha1("DB03AEC0586929BF8B4EFAF54BAD0AC5509FD8BE") or
		androguard.certificate.sha1("6EAC736931F21F7ED5525A69B52BF7D3274542A1") or		
   		androguard.certificate.sha1("C21676E8EFBA88235C8FCE4D023797173401FE3C") or
		androguard.certificate.sha1("01AAD3AA7949A89B36F1F44AFA266F3113C6E615") or
		androguard.certificate.sha1("7F565F25BA98DEF913538F411914EF0EE74F10EE")
		
}
