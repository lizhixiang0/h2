/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Russian domain
    Rule id: 1197
    Created at: 2016-02-12 07:12:28
    Updated at: 2016-02-14 11:30:56
    
    Rating: #0
    Total detections: 21298
*/

rule russian_domain: adware
{
	strings:
		$a = "zzwx.ru"

	condition:
		$a
		
}
