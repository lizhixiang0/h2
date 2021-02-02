/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: Dropper
    Rule id: 588
    Created at: 2015-06-16 07:54:22
    Updated at: 2015-08-06 15:20:16
    
    Rating: #0
    Total detections: 85
*/

rule dropper:realshell {
	meta:
		source = "https://blog.malwarebytes.org/mobile-2/2015/06/complex-method-of-obfuscation-found-in-dropper-realshell/"
	strings:
		//$a = "hexKey:"
		$b = "Decrypt.malloc.memset.free.pluginSMS_encrypt.Java_com_skymobi_pay_common_util_LocalDataDecrpty_Encrypt.strcpy"
	
	condition:
		$b
}
