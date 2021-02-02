/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: RaVi
    Rule name: New Ruleset
    Rule id: 2857
    Created at: 2017-05-30 22:55:40
    Updated at: 2017-05-30 22:56:15
    
    Rating: #0
    Total detections: 6
*/

rule regla_practica
{
	meta:
		description = "PracticaC"
		sample = "7dab21d4920446027a3742b651e3ef8d"

	strings:
		$string_a = "3528-3589"
		$string_b = "/app/remote/forms/"
		$string_c = "IIII"
		$string_d = "slempo"
		
	condition:
		$string_a and $string_b and $string_c and $string_d
		}
