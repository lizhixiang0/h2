/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: SadFud
    Rule name: Metasploit_Meterpreter_Payload
    Rule id: 2513
    Created at: 2017-04-20 22:58:13
    Updated at: 2017-04-20 22:59:21
    
    Rating: #0
    Total detections: 4071
*/

import "androguard"

rule Metasploit_Payload
{
  meta:
      author = "https://www.twitter.com/SadFud75"
      information = "Detection of payloads generated with metasploit"
  strings:
      $s1 = "-com.metasploit.meterpreter.AndroidMeterpreter"
      $s2 = ",Lcom/metasploit/stage/MainBroadcastReceiver;"
      $s3 = "#Lcom/metasploit/stage/MainActivity;"
      $s4 = "Lcom/metasploit/stage/Payload;"
      $s5 = "Lcom/metasploit/stage/a;"
      $s6 = "Lcom/metasploit/stage/c;"
      $s7 = "Lcom/metasploit/stage/b;"
  condition:
      androguard.package_name("com.metasploit.stage") or any of them
}
