/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: SadFud
    Rule name: Ransomware
    Rule id: 2510
    Created at: 2017-04-20 17:05:46
    Updated at: 2017-04-24 11:30:59
    
    Rating: #0
    Total detections: 33855
*/

import "androguard"

rule ransomware
{
  meta:
      author = "https://www.twitter.com/SadFud75"
  strings:
      $s1 = "The penalty set must be paid in course of 48 hours as of the breach" nocase
      $s2 = "following violations were detected" nocase
      $s4 = "all your files are encrypted" nocase
      $s5 = "your device has been blocked" nocase
      $s6 = "department of justice" nocase
      $s7 = "remaining time to pay" nocase
      $s8 = "your phone has been blocked" nocase
  condition:
      any of them or androguard.service("com.h.s")
}
