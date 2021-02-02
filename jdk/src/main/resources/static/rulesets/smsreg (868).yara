/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asanchez
    Rule name: SMSReg
    Rule id: 868
    Created at: 2015-09-28 05:22:18
    Updated at: 2015-09-28 05:40:59
    
    Rating: #0
    Total detections: 123505
*/

rule SMSRegister
{
	meta:
		description = "This rule detects applications that register sms and send"
		sample = "ec488970bf7152726220ab75f83f8aaa48d824d942fb94ef52a64b6901f48274"
		sample2 = "ed73113b63325d5060f0d39a827bc32281e005c1de8d9dbea2cd583358382870"
		sample3 = "ec4c23a0eba77f68e88e331bc3b88162a18c5c27677858d8698ba8a47a564b37"

	strings:
		$key = "\"cmd_key\":\"DJ_jh_2\""
		$ip = "182.92.21.219:10789"
		$number1 = "{\"NUM\":\"10086\"}"
		$number2 = "{\"NUM\":\"10665110\"}"
		$number3 = "{\"NUM\":\"11185*\"}"
		$number4 = "{\"NUM\":\"12110*\"}"
		$number5 = "{\"NUM\":\"12114*\"}"
		$number6 = "{\"NUM\":\"123??\"}"
		$number7 = "{\"NUM\":\"12520*\"}"
		$number8 = "{\"NUM\":\"13800138000\"}"
		$number9 = "{\"NUM\":\"7022288\"}"
		$number10 = "{\"NUM\":\"955*\"}"

	condition:
		($key and $ip) and (any of ($number*))
}
