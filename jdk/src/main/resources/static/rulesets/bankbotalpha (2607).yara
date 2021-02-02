/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: skeptre
    Rule name: BankbotAlpha
    Rule id: 2607
    Created at: 2017-05-02 17:58:22
    Updated at: 2017-05-03 17:08:12
    
    Rating: #0
    Total detections: 261
*/

import "androguard"
import "file"
import "cuckoo"


rule BankbotAlpha
{
	meta:
		description = "This rule detects BankBot alpha samples"
		sample = "019bf3ab14d5749470e8911a55cdc56ba84423d6e2b20d9c9e05853919fc1462"
		more_info = "https://blog.fortinet.com/2017/04/26/bankbot-the-prequel"

	strings:
		$b_1 = "cclen25sm.mcdir.ru"
		$b_2 = "firta.myjino.ru"
		$b_3 = "adminko.mcdir.ru"
		$b_4 = "atest.mcdir.ru"
		$b_5 = "cclen25sm.mcdir.ru"
		$b_6 = "probaand.mcdir.ru"
		$b_7 = "firta.myjino.ru"
		$b_8 = "ranito.myjino.ru"
		$b_9 = "servot.myjino.ru"
		$b_10 = "jekobtrast1t.ru"
		$b_11 = "kinoprofi.hhos.ru"
		$a = "private/add_log.php"

	condition:
		$a and 
		any of ($b_*)
		
}
