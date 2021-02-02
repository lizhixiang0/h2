/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: BankBots
    Rule id: 4312
    Created at: 2018-04-05 11:54:37
    Updated at: 2018-09-20 08:34:40
    
    Rating: #0
    Total detections: 40
*/

rule BankBot
{
	strings:
	  $ = "cmdline"
	  $ = "receiver_data.php"
	  $ = "set.php"
	  $ = "tsp_tsp.php"

	condition:
		all of them
		
}

rule BankBot2
{
    strings:
		$a = /\/\/[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}\//
		$a1 = /index.php.action=command/
		
		$b = /adobe update/ nocase
		$b1 = /whatsapp/ nocase
		
		$c = /Confirm credit card details/ nocase
		

    condition:
		all of ($a*) and 1 of ($b*) and $c
		

}

rule BankBot1
{
	strings:
	  $a = "22http://ffpanel.ru/client_ip.php?key="

	condition:
		$a
		
}
