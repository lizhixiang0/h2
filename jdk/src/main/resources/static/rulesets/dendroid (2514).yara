/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: SadFud
    Rule name: Dendroid
    Rule id: 2514
    Created at: 2017-04-20 23:34:14
    Updated at: 2017-04-21 10:53:35
    
    Rating: #0
    Total detections: 238
*/

rule Trojan_Dendroid
{
  meta:
      author = "https://www.twitter.com/SadFud75"
      description = "Detection of dendroid trojan"
  strings:
      $s1 = "/upload-pictures.php?"
      $s2 = "/get-functions.php?"
      $s3 = "/new-upload.php?"
      $s4 = "/message.php?"
      $s5 = "/get.php?"
  condition:
      3 of them
}
