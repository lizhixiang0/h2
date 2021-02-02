/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: fdiaz
    Rule name: PaymentSMS
    Rule id: 870
    Created at: 2015-09-28 19:51:09
    Updated at: 2016-08-02 12:03:42
    
    Rating: #0
    Total detections: 302444
*/

import "androguard"

rule paymentsSMS
{
	meta:
		description = "Connects to remote server and tries to charge the user using his data and sends SMS"
		

	strings:
		$a = "http://112.126.69.51/imei_mobile.php?imei="
		$b = "http://api.taomike.com/install_zhubao.php"
		$c = "http://112.126.69.51/order_lost.php"
		$d = "http://112.126.69.51/install_report.php"
		$e = "http://112.74.111.56:9039/gamesit/puburl"
		$f = "http://194.87.232.236/mos_metro/?deviceID="
	condition:
		 androguard.url(/112\.126\.69\.51/) or $a or $b or $c or $d or $e or $f
		
}
