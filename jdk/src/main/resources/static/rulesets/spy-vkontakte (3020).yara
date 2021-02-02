/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: Spy-Vkontakte
    Rule id: 3020
    Created at: 2017-06-22 11:57:50
    Updated at: 2017-06-23 09:05:35
    
    Rating: #0
    Total detections: 15
*/

import "androguard"

rule urls
{
	meta:
		description = "Lukas Stefanko https://twitter.com/LukasStefanko/status/877842943142281216"

	strings:
		$ = "0s.nrxwo2lo.ozvs4y3pnu.cmle.ru"
		$ = "0s.nu.ozvs4y3pnu.cmle.ru"
		$ = "0s.nu.n5vs44tv.cmle.ru"
		$ = "navidtwobottt.000webhostapp.com/rat/upload_file.php"
		$ = "telememberapp.ir/rat/upload_file.php"

	condition:
		1 of them
		
}
