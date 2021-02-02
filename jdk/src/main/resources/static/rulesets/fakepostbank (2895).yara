/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: joseangel
    Rule name: FakePostBank
    Rule id: 2895
    Created at: 2017-05-31 18:34:04
    Updated at: 2017-05-31 19:54:41
    
    Rating: #0
    Total detections: 43
*/

/*
 * Regla para detectar la ocurrencia de nuestra muestra 
 */
rule FakePostBank {
meta:
descripton= "Regla para Detectar Fake Post Bank"

strings:
		$a = "http://185.62.188.32/app/remote/"
		$b = "intercept_sms"
		$c = "unblock_all_numbers"
		$d = "unblock_numbers"
		$e = "TYPE_INTERCEPTED_INCOMING_SMS"
		$f = "TYPE_LISTENED_INCOMING_SMS"

	condition:
		$a and $b and ($c or $d or $e or $f)
}
