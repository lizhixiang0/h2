/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: register
    Rule name: XBOT
    Rule id: 1221
    Created at: 2016-02-19 04:12:11
    Updated at: 2016-04-29 08:21:17
    
    Rating: #0
    Total detections: 38
*/

import "androguard"
import "file"
import "cuckoo"


rule ms : XBOT
{
	meta:
		description = "XBOT"
		source = "http://researchcenter.paloaltonetworks.com/2016/02/new-android-trojan-xbot-phishes-credit-cards-and-bank-accounts-encrypts-devices-for-ransom/"

	strings:
		$a0 = /melon25.ru+/
		$a1 = /81.94.205.226:8021+/
		$a2 = /104.219.250.16:8022+/
		$a3 = /52.24.219.3\/action.php+/
		$a4 = /192.227.137.154\/request.php+/
		$a5 = /23.227.163.110\/locker.php+/
		$a6 = /market155.ru\/Install.apk+/
		$a7 = /illuminatework.ru\/Install.apk+/
		$a8 = /yetiathome15.ru\/Install.apk+/
		$a9 = /leeroywork3.co\/install.apk+/
		$a10 = /morning3.ru\/install.apk+/
		$a11 = /\+79262+/
		
	condition:
		file.sha1("dfda8e52df5ba1852d518220363f81a06f51910397627df6cdde98d15948de65") or
		file.sha1("e905d9d4bc59104cfd3fc50c167e0d8b20e4bd40628ad01b701a515dd4311449") or
		file.sha1("f2cfbc2f836f3065d5706b9f49f55bbd9c1dae2073a606c8ee01e4bbd223f29f") or
		file.sha1("029758783d2f9d8fd368392a6b7fdf5aa76931f85d6458125b6e8e1cadcdc9b4") or
		file.sha1("1264c25d67d41f52102573d3c528bcddda42129df5052881f7e98b4a90f61f23") or
		file.sha1("20bf4c9d0a84ac0f711ccf34110f526f2b216ae74c2a96de3d90e771e9de2ad4") or
		file.sha1("33230c13dcc066e05daded0641f0af21d624119a5bb8c131ca6d2e21cd8edc1a") or
		file.sha1("4b5ef7c8150e764cc0782eab7ca7349c02c78fceb1036ce3064d35037913f5b6") or
		file.sha1("7e939552f5b97a1f58c2202e1ab368f355d35137057ae04e7639fc9c4771af7e") or
		file.sha1("93172b122577979ca41c3be75786fdeefa4b80a6c3df7d821dfecefca1aa6b05") or
		file.sha1("a22b55aaf5d35e9bbc48914b92a76de1c707aaa2a5f93f50a2885b0ca4f15f01") or
		file.sha1("d082ec8619e176467ce8b8a62c2d2866d611d426dd413634f6f5f5926c451850") or
		file.sha1("a94cac6df6866df41abde7d4ecf155e684207eedafc06243a21a598a4b658729") or
		file.sha1("58af00ef7a70d1e4da8e73edcb974f6ab90a62fbdc747f6ec4b021c03665366a") or
		file.sha1("7e47aaa8a1dda7a413aa38a622ac7d70cc2add1137fdaa7ccbf0ae3d9b38b335") or
		file.sha1("d1e5b88d48ae5e6bf1a79dfefa32432b7f14342c2d78b3e5406b93ffef37da03") or
		file.sha1("c2354b1d1401e31607c770c6e5b4b26dd0374c19cc54fc5db071e5a5af624ecc") or
		file.sha1("12f75b8f58e1a0d88a222f79b2ad3b7f04fd833acb096bb30f28294635b53637") or		
		file.sha1("1b84e7154efd88ece8d6d79afe5dd7f4cda737b07222405067295091e4693d1b") or
		file.sha1("616b13d0a668fd904a60f7e6e18b19476614991c27ef5ed7b86066b28952befc") or	
		file.sha1("2e2173420c0ec220b831f1c705173c193536277112a9716b6f1ead6f2cad3c9e") or
		file.sha1("595fa0c6b7aa64c455682e2f19d174fe4e72899650e63ab75f63d04d1c538c00") or
		$a0 or $a1 or $a2 or $a3 or $a4 or $a5 or $a6 or $a7 or $a8 or $a9 or $a10 or $a11
		
}
