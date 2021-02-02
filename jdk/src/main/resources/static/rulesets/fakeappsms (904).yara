/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: fdiaz
    Rule name: FakeAPP/SMS
    Rule id: 904
    Created at: 2015-10-09 11:32:14
    Updated at: 2016-03-23 19:30:30
    
    Rating: #0
    Total detections: 314735
*/

import "androguard"

rule AgeWap
{
	meta:
		description ="Rule to detect AgeWap apps. They send fraudulent SMS - Very small size always."

	condition:
		androguard.certificate.issuer(/C=RU\/ST=Unknown\/L=Moscow\/O=AgeWap\/OU=AgeWap Corp\.\/CN=AgeWap/) and androguard.permission(/android.permission.SEND_SMS/)
		
}


rule Londaniga
{
	meta:
		description = "Rule to detect Londaniga fake apps. SMS Fraud in most."
	
	condition:
		androguard.certificate.issuer(/lorenz@londatiga.net/) and androguard.permission(/android.permission.SEND_SMS/)		
}

rule Londaniga2 : urls
{
	meta: 
		description = "IPs receiving info from user in Londaniga apps." 
	

	strings:
		$a = "http://211.136.165.53/adapted/choose.jsp?dest=all&chooseUrl=QQQwlQQQrmw1sQQQpp66.jsp"
		$b = "http://211.136.165.53/wl/rmw1s/pp66.jsp"
		
	condition:
		all of them
}

rule gsr
{
	meta:
		description = "Fakes Apps (Instagram Hack) and adds very intrusive ads"
		sample = "42a5fe37f94e46b800189d7412a29eee856248f9a2ebdc3bc18eb0c6ae13b491"
	condition:
		androguard.certificate.sha1("943BC6E0827F09B050B02830685A76734E566168")
}

rule smsReg {
	strings:
		$mmmm = "http://zhxone.com/"
		$oooo = "http://coco.zhxone.com"
		$nnnn = "http://tools.8282.net"
		$jjjj = "http://coco.zhxone.com/tools/datatools"
 		$pppp = "www.zhxone.com/service.php?api=apkinstall&pk=%s&aid=1000002"
 		$qqqq = "http://auto.zhxone.com/adredirect.php?ct=%d&ag=%s&u=%s"
		$rrrr = "http://auto.zhxone.com/adredirect.php?ct=%d"
		$ssss = "http://tools.8782.net/stat.php?ac=upsts&did=%s&ag=%d&md=%s&sdk=%s&rel=%s&cp=%s&s=1"
		$tttt = "www.zhxone.com/service.php?api=uslog&n=hdus_start&u=%s"
		$uuuu = "http://tools.8782.net/stat.php?ac=uperr&did=%s&tg=%s&er=%s"
		
	condition:
		any of them
}

rule PornSMS {

	 condition:
	 	androguard.package_name("com.shenqi.video.ycef.svcr") or 
		androguard.package_name("com.shenqi.video.tjvi.dpjn)") or
		androguard.package_name("dxas.ixa.xvcekbxy") or
		androguard.package_name("com.video.ui") or 
		androguard.package_name("com.qq.navideo") or
		androguard.package_name("com.android.sxye.wwwl") or
		androguard.certificate.issuer(/llfovtfttfldddcffffhhh/)
		}
