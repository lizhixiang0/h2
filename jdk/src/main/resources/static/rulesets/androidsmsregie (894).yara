/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: fdiaz
    Rule name: Android/SMSreg.IE
    Rule id: 894
    Created at: 2015-10-07 21:02:39
    Updated at: 2018-01-04 16:23:57
    
    Rating: #0
    Total detections: 137052
*/

import "androguard"


rule smsriskware
{
	meta:
		description = "Payments(sms), storing gps location into .db files and sending through http"
		

	strings:
		$a = "http://112.74.106.240:7878/port/SInit/"
		$b = "http://112.74.106.240:7878/port/Sbill/"
		$c = "http://wiipay.cxso.cn/xml/listA.txt"
		
	condition:
		all of them 
		
}

rule adware {
	meta: 
		description = "Sends SMS/MMS - Installs adware"
	
	strings:
		$a = "http://115.28.52.43:9000/tabscr/appclient/fetchList!down.do?imei="
		$b = "http://sy.ppcool.com.cn:8089/pachong-server"
		$c = "http://sy.ppcool.com.cn:8089/pachong-server/download.service?"
		$d = "http://121.199.29.243/MobileInfoPlatform/ssi/encryption.action?v=14&p="
		$e = "http://121.199.29.243/MobileInfoPlatform/ssi/saveUser.action?v=14&p="
		$f = "http://211.151.131.83/mms/di/docheck.action"
		$g = "http://121.199.29.243/MobileInfoPlatform/ssi/applicationStatus.action?v=14&p="
	
	condition:
		any of them
		}

rule fakeAV
{
  meta:
  	description = "Redirects to fake AV page to install / send later sms / ads"
	
  strings:
  	$a = "http://www.antivirus-pro.us/downloads/list.txt"
	
  condition:
  	$a
	
}

rule smsSender
{
  meta:
  	description = "Has a list of countries and phones inside a .txt file. Apparently using some kind of code from BASICSMSSENDER"
  
  strings:
    $a = "SmsInfo() C-tor"
	$b = "dcSmsCount_"
	$c = "\n*****BINARY MESSAGE*****\n"
	
  condition:
    all of them 

}

rule fakeInstaller {

	meta:
		description = "Fake installer - Same signature always encrypted with RSA"
		
	strings:
		$a = "PKCS5Padding"
		$b = "Blowfish"
		$c ="ECB"
		$f= "http://qpclick.com/"
		
	condition:
		all of them 
}

rule riskWare {
	meta:
		description = "Riskware, installing thirdparty APKs and adware"
	condition:
		androguard.certificate.sha1("4D1C1D21519F3B03858627D624BE87DA961E83EC")
}

rule fakeInstallerSig {

	meta:
		description = "Fake installer - Same signature always encrypted with RSA"
		
	condition:
			androguard.certificate.sha1("17:42:6e:74:e2:96:d3:fa:31:01:04:62:08:d9:c7:84:1d:73:89:0c:de:de:80:a6:df:5e:ca:c6:43:1d:bc:37:57:c4:ad:e9:21:30:f4:0d:02:7d:f7:19:5a:54:ce:2a:6f:ee:85:02:32:50:23:74:7b:87:4d:ee:92:e1:63:24:b8:cc:16:50:62:0f:6e:f3:09:cd:75:2a:93:95:95:e6:4c:be:a4:73:27:4a:5b:5b:1c:f4:ef:02:cd:f8:6e:cc:30:5c:7e:f9:fe:54:96:f9:78:73:62:40:6e:10:ee:3d:9f:85:57:cf:59:25:09:06:c6:01:61:a1:3a:56:cf:7f:14:84:ed:4b:ff:6b:91:49:0a:ca:23:98:3c:84:c7:35:65:21:19:3e:2c:41:42:47:cd:74:84:4a:f3:fa:aa:b3:ed:ff:40:8b:ed:4c:a7:df:d1:9c:49:b1:38:49:bf:aa:20:e0:28:b9:04:07:44:d0:f4:e7:64:4b:29:a6:7a:ac:de:24:79:59:95:b2:fe:98:e6:61:08:dd:a8:9e:fc:59:51:49:f4:87:c4:0a:0b:e7:dc:09:73:86:a9:71:46:54:6c:11:11:bb:73:b8:5f:fa:c4:e0:03:85:0b:4c:19:f6:29:d3:1b:d8:c2:bc:da:c5:1b:6a:a0:6c:7b:89:5b:51")
		
}
