/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: regiakb
    Rule name: slempo
    Rule id: 4515
    Created at: 2018-06-11 10:24:35
    Updated at: 2018-06-11 10:39:52
    
    Rating: #0
    Total detections: 61
*/

import "androguard"

rule Practica4

{
	meta:
		description = "Practica4-Slempo"
		sample = "7dab21d4920446027a3742b651e3ef8d"		

	strings:
	
		$a = "org/slempo/service" 
		$b = "http://185.62.188.32/app/remote/"
		$c = "http://185.62.188.32/app/remote/forms"
		$d = "org.slempo.service"
		
	condition:
		1 of them
	
}
