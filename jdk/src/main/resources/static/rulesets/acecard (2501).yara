/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: SadFud
    Rule name: Acecard
    Rule id: 2501
    Created at: 2017-04-20 09:08:41
    Updated at: 2017-04-20 09:57:03
    
    Rating: #0
    Total detections: 33
*/

import "androguard"

rule Banker_Acecard
{
  meta:
      author = "https://twitter.com/SadFud75"
      more_information = "https://threats.kaspersky.com/en/threat/Trojan-Banker.AndroidOS.Acecard/"
      samples_sha1 = "ad9fff7fd019cf2a2684db650ea542fdeaaeaebb 	53cca0a642d2f120dea289d4c7bd0d644a121252"
  strings:
      $str_1 = "Cardholder name"
      $str_2 = "instagram.php"
  condition:
      ((androguard.package_name("starter.fl") and androguard.service("starter.CosmetiqFlServicesCallHeadlessSmsSendService")) or androguard.package_name("cosmetiq.fl") or all of ($str_*)) and androguard.permissions_number > 19
}
