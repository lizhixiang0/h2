/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: Trojan-SMS AndroidOS GCM
    Rule id: 1565
    Created at: 2016-07-04 14:51:18
    Updated at: 2016-07-05 11:35:13
    
    Rating: #0
    Total detections: 385
*/

rule GCM
{
	meta:
		description = "Trojan-SMS AndroidOS GCM"
		sample = "81BB2E0AF861C02EEAD41FFD1F08A85D9490FE158586FA8509A0527BD5835B30"

	strings:
		$a = "whatisthefuckingshirtmazafakayoyonigacomon.ru"

	condition:
		all of them
		
		
}
