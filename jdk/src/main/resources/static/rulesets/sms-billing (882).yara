/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: fdiaz
    Rule name: SMS Billing
    Rule id: 882
    Created at: 2015-10-03 17:37:29
    Updated at: 2015-10-03 17:44:30
    
    Rating: #0
    Total detections: 58381
*/

import "androguard"

rule smsBilling
{
	meta:
		description = "Sends SMS and connects to remote host."
		

	strings:
		$a = "http://115.28.56.28:8080/pay/GengYuanSDK.js"
		$b = "http://115.28.56.28:8080/pay/client_bill"
        $c =  "http://115.28.56.28:8080/pay/client_init"
		$d = "http://115.28.56.28:8080/pay/client_mo_lose"
		$e = "http://115.28.56.28:8080/pay/client_pay"
		$f = "http://115.28.56.28:8080/pay/error"
		$g =  "http://115.28.56.28:8080/pay/jarData.jar"
		$h = "http://115.28.56.28:8080/v/clent_confirm"
		$i = "http://115.28.56.28:8080/v/client_key?key="
		$j = "http://115.28.56.28:8080/v/index.jsp"
		$k = "http://121.42.14.182:8080/v/indexs.jsp?v=7"
		$l = "http://121.42.14.182:8080/v/video.jsp"
		$m = "http://192.168.1.158:8080/NetTest/ext.jar"
		$n = "http://blog.sina.com.cn/u/1559825985"
		$u = "http://www.soimsi.com/imsi.html?phone="


	condition:
		any of them
		
}
