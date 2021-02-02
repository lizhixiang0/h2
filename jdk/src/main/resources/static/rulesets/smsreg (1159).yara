/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: SMSReg
    Rule id: 1159
    Created at: 2016-01-26 13:30:45
    Updated at: 2016-01-26 13:32:21
    
    Rating: #0
    Total detections: 422
*/

rule SMSReg
{
	meta:
		description = "This rule detects SMSReg trojan"
		sample = "b9fd81ecf129d4d9770868d7a075ba3351dca784f9df8a41139014654b62751e"

	strings:
		$a = "before send msg to cu server optaddr"
		$b = "Service destory"
		$c = "Enter start service"
		$d = "The sim card in this phone is not registered, need register"

	condition:
		all of them
		
}
