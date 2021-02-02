/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: SMSFraud
    Rule id: 1139
    Created at: 2016-01-20 10:56:58
    Updated at: 2016-02-08 08:23:16
    
    Rating: #0
    Total detections: 22135
*/

rule smsfraud
{
	meta:
		description = "This rule detects a kind of SMSFraud trojan"
		sample = "265890c3765d9698091e347f5fcdcf1aba24c605613916820cc62011a5423df2"
		sample2 = "112b61c778d014088b89ace5e561eb75631a35b21c64254e32d506379afc344c"

	strings:
		$a = "E!QQAZXS"
		$b = "__exidx_end"
		$c = "res/layout/notify_apkinstall.xmlPK"
		
		
	condition:
		all of them
		
}

rule smsfraud2 {
        meta:
                sample = "0200a454f0de2574db0b58421ea83f0f340bc6e0b0a051fe943fdfc55fea305b"
                sample2 = "bff3881a8096398b2ded8717b6ce1b86a823e307c919916ab792a13f2f5333b6"

        strings:
                $a = "pluginSMS_decrypt"
                $b = "pluginSMS_encrypt"
                $c = "__dso_handle"
                $d = "lib/armeabi/libmylib.soUT"
                $e = "]Diok\"3|"
        condition:
                all of them
}
