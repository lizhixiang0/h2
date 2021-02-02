/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Marcher.2
    Rule id: 1301
    Created at: 2016-03-18 12:09:45
    Updated at: 2016-06-06 09:56:50
    
    Rating: #1
    Total detections: 1408
*/

rule marcher_v2
{
	meta:
		description = "This rule detects a new variant of Marcher"
		sample = "27c3b0aaa2be02b4ee2bfb5b26b2b90dbefa020b9accc360232e0288ac34767f"
		author = "Antonio S. <asanchez@koodous.com>"

	strings:
		$a = /assets\/[a-z]{1,12}.datPK/
		$b = "mastercard_img"
		$c = "visa_verifed"

	condition:
		all of them

}
