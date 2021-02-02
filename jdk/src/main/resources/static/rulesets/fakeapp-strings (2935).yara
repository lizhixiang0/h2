/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: jcarneiro
    Rule name: FakeApp Strings
    Rule id: 2935
    Created at: 2017-06-06 16:33:09
    Updated at: 2018-06-12 12:02:00
    
    Rating: #0
    Total detections: 561
*/

rule blacklisted_strings: jcarneiro
{
	meta:
		description = "This rule fake apps strings"

	strings:
		$a = "application has been update to run the application"
		$b = "com.evasoft.siteredrect"
		$c = "Correct update do only with 3G/4G internet connection. Please turn-off WiFi-connection and click Update button"
		$d = "disable WiFi, and then click Download"
		$e = "download [new version!]"
		$f = "for app there is an update"
		$g = "install and open 3 of our completely free apps"
		$h = "install and open 3 of our complety free apps"
		$i = "Install apk....please wait!"
		$j = "necassary to make review and rate 5 stars"
		$k = "necessary to make review and rate 5 stars"
		$l = "need to download 3 free games"
		$m = "Please update the version of the aptoide client"
		$n = "rate us with 5 stars to open the app"
		$o = "Thank you for choosing APTOIDE"
		$p = "Thank you that you chose Aptoide"
		$q = "The button INSTALL will be atcive after installation of the application below"
		$r = "This free version is supported by Ads, you need to check some ads to continue"
		$s = "TO INSTALL GAME, CLICK TO ACTIVATE"
		$t = "turn off Wi-Fi and turn on 3G"
		$u = "You have 18 year old?"
		$v = "you have not opened at least once the 3 applications you just installed"
		$w = "You need to check ads before continue."
		

	condition:
		any of them
}
