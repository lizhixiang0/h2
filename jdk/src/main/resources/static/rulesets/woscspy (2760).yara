/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: agucova
    Rule name: WoscSpy
    Rule id: 2760
    Created at: 2017-05-24 23:40:51
    Updated at: 2018-04-02 21:16:15
    
    Rating: #1
    Total detections: 35
*/

import "androguard"

rule WoscSpy 
{
  meta:
    description = "Rule for the detection of a Spyware by 'Wosc Development'"
    sample = "0e3324dd8ea86a6326bb23a79d3b3a02d1ee7068d934e1f2ce2300eaaf6630b1"
  strings:
    $mainactivity = "ActivityActivacionInicial"
  condition:
	androguard.certificate.sha1("0E6DC2A27BA2F155C51D8D5AF36D140F92AE203C") or
	androguard.certificate.sha1("89F539729637A67C6BB5A218B00CB3EBDDE2D18D") or
	androguard.certificate.sha1("435CEF8BDA4A8EEF787B0EA6B90E60ECE804459B") or
	androguard.url(/wosc\.net/) or
	androguard.url(/espiar-celular\.com/) or
	androguard.package_name("com.espiarCelular") or
	androguard.package_name("com.espCel2") or
	androguard.package_name(/\*.wosc.\*/) or
	$mainactivity
  }
