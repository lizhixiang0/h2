/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: SadFud
    Rule name: Androrat
    Rule id: 2526
    Created at: 2017-04-22 10:58:37
    Updated at: 2017-04-22 10:59:03
    
    Rating: #0
    Total detections: 1022
*/

rule Trojan_Androrat
{
  meta:
      Author = "https://www.twitter.com/SadFud75"
  strings:
      $s_1 = "Hello World, AndroratActivity!" wide ascii
      $s_2 = "Lmy/app/client/AndroratActivity;" wide ascii
      $s_3 = "Androrat.Client.storage" wide ascii
  condition:
      any of them
}
