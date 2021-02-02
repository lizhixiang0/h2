/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: kuckuck2000
    Rule name: Banker Catalites
    Rule id: 4021
    Created at: 2018-01-19 09:45:18
    Updated at: 2018-01-30 09:54:55
    
    Rating: #0
    Total detections: 47
*/

rule detection
{
    strings:
	  $ = "Added %1$s to %2$s balance"  nocase
	  $ = "money_was_add"  nocase
	  //$ = "Android System Update"  nocase
	  $ = "!!Touch to sign in to your account"  nocase
	  $ = "You will be automatically charged %1$s"  nocase
	  $ = "adm_win"  nocase
	  $ = "shhtdi"  nocase
	  $ = "chat_interface"  nocase
	  $ = "chat_receive"  nocase
	  $ = "chat_sent"  nocase
	  $ = "chat_row" nocase

	
	condition:
		all of them

}
