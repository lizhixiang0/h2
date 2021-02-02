/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: Locker Cokri
    Rule id: 1933
    Created at: 2016-10-25 08:34:54
    Updated at: 2016-10-25 08:37:19
    
    Rating: #0
    Total detections: 8
*/

rule Ransom:Cokri {
	meta:
	description = "Trojan Locker Cokri"
		
	strings:
	$ = "com/example/angrybirds_test/MyService" 
	$ = "world4rus.com"
	$ = "api.php/?devise"
	
	condition:
	all of them

}
