/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: KikDroid
    Rule id: 4268
    Created at: 2018-03-14 12:32:52
    Updated at: 2018-04-16 09:20:58
    
    Rating: #0
    Total detections: 0
*/

rule KikDroid {

	strings:
		$s1 = "wss://arab-chat.site"
		$s2 = "wss://chat-messenger.site"
		$s3 = "wss://chat-world.site"
		$s4 = "wss://free-apps.us"
		$s5 = "wss://gserv.mobi"
		$s6 = "wss://kikstore.net"
		$s7 = "wss://network-lab.info"
		$s8 = "wss://onlineclub.info"
		$a1 = "/data/kik.android"
		$a2 = "spydroid"
	
	condition:

		1 of ($s*) and 1 of ($a*)

}
