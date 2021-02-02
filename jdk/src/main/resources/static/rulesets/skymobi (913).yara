/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: fdiaz
    Rule name: Skymobi
    Rule id: 913
    Created at: 2015-10-10 21:02:49
    Updated at: 2015-10-12 20:58:29
    
    Rating: #0
    Total detections: 1590115
*/

import "androguard"

rule SkyMobiVariant
{
	meta:
		description = "Variant of Skymobi / SMS Pay / Riskware"
		sample = "80701cf847caf5ddf969ffcdf39144620b3692dc50c91663963a3720ee91e796"

	condition:
 androguard.certificate.sha1("62:71:54:7B:66:8C:E8:81:20:82:49:F8:59:5F:53:15:E3:90:EB:2E")
	
}

rule SkymobiPorn
{
	meta:
		description = "Skymobi variant - Ads / SMS"
		sample = "828e4297a68ced35e16a0bc21e746f7d93c74166104597845bb827709311ceb3"
	
	strings:
		  $a = "http://121.52.218.66:8011/request_v2.php?"
		  $b = "http://182.92.109.55:10789/userBehaviour/cmcc/mm/single/login?version=1.0.0.7&pid="
		  $c = "http://121.52.218.66:8009/alipayto_v2.php"
		  $d = "http://116.205.4.157:9900/dorecharge3.do"
		  $e = "http://121.52.218.66:8008/request_v2.php"
		  $f = "http://117.135.131.209:808/xiyuerdo/noti_url.php"
		  $g = "http://116.205.4.157:9900/dorecharge2.do"
		  $h = "http://117.135.131.209:808/baidurdo/noti_url.php"
		  $i = "http://111.13.47.76:81/open_gate/web_game_fee.php"
		  $j ="http://118.26.235.115:8080/rdo/services/rdo/shortNotify?channel=$channel&feeCode=$feeCode&schannel=$schannel"
		  $k = "http://182.92.109.55:10789/userBehaviour/cmcc/mm/single/action?version=1.0.0.7&pid="
		  $l ="http://111.13.91.31:12000/feecenter/api/create_order"
		  $m = "http://sms2.upay360.com/geturl.php"
		  $n = "http://111.13.47.76:81/open_gate/web_game_callback.php"
		  $o = "http://121.52.218.66:8012/request_v2.php"
		  $p = "http://182.92.109.55:10789/userBehaviour/cmcc/mm/single/sys?version=1.0.0.7&pid="
		  $q = "http://121.52.218.66:8011/request_v2.php"
		  $r = "http://221.179.131.90/0903?http://111.13.47.76:81/open_gate/web_game_fee.php"
		  $s = "http://121.52.218.66:8009/alipayto_v2.php?"
	
	condition: 
		any of them 
}
