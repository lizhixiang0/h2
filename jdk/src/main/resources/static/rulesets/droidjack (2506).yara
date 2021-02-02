/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: SadFud
    Rule name: Droidjack
    Rule id: 2506
    Created at: 2017-04-20 11:11:15
    Updated at: 2017-04-20 11:12:10
    
    Rating: #-2
    Total detections: 2434
*/

import "androguard"

rule Trojan_Droidjack
{
  meta:
      author = "https://twitter.com/SadFud75"
  condition:
      androguard.package_name("net.droidjack.server") or androguard.activity(/net.droidjack.server/i)
}
