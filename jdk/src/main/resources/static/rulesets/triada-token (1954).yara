/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: NikitaBuchka
    Rule name: Triada token
    Rule id: 1954
    Created at: 2016-11-09 08:51:48
    Updated at: 2016-11-09 09:06:36
    
    Rating: #1
    Total detections: 788
*/

rule koodous : official
{
	meta:
		description = "Triada token(https://securelist.com/analysis/publications/74032/attack-on-zygote-a-new-twist-in-the-evolution-of-mobile-threats/)"
		sample = "0cc9bcf8ae60a65f913ace40fd83648e"

	strings:
		$a = {63 6f 6e 66 69 67 6f 70 62}

	condition:
		$a
		
}
