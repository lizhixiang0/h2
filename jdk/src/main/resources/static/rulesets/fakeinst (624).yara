/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: jmesa
    Rule name: FakeInst
    Rule id: 624
    Created at: 2015-06-22 14:46:35
    Updated at: 2016-05-26 09:53:22
    
    Rating: #1
    Total detections: 83897
*/

import "androguard"

rule FakeInst
{
	meta:
        description = "FakeInst evidences"
		
	strings:
		$1 = "res/raw/mccmnc.txt" wide ascii
		$2 = "Calculated location by MCCMNC" wide ascii
		$3 = "getCost" wide ascii

   	condition:
		all of them
}

rule FakeInst_certs
{
	meta:
		description = "FakeInst installer from fake developers"
		sample = "acce1154630d327ca9d888e0ecf44a1370cf42b3b28a48446a9aaaec9ec789c3"
		
	condition:
		androguard.certificate.sha1("C67F8FC63E25C1F2D3D3623210D126BC96AFEE69") or
		androguard.certificate.sha1("FB2FD4D89D7363E6386C865247825C041F23CDEB") or
		androguard.certificate.sha1("9AD4DB5F64C6B12106DCAE54A9759154C56E27E1") or
		androguard.certificate.sha1("0A721AF65BBB389EA9E224A59833BD3FD92F4129") or
		androguard.certificate.sha1("5D66125A5FAE943152AE83D5787CDCFD1C579F4E")	or	
		androguard.certificate.sha1("2260A1A17C96AF2C8208F0C0A34CF3B87A28E960")
}

rule FakeInst_offers_xmls
{
	meta:
        description = "FakeInst evidences offers XML"
		
	strings:
		$0 = "strings.xml" wide ascii
		$1 = "app_name" wide ascii
		$2 = "apps_dir_wasnt_created" wide ascii
		$3 = "dialog_file_downloads_text" wide ascii
		$4 = "dialog_no_button" wide ascii
		$5 = "dialog_yes_button" wide ascii
		$6 = "download_file" wide ascii
		$7 = "error_sms_sending" wide ascii
		$8 = "full_offerts_text" wide ascii
		$9 = "i_disagree_offert" wide ascii

   	condition:
		all of them
}

rule FakeInst_v2
{
	meta:
        description = "FakeInst evidences v2"
		
	strings:
		$1 = "loadSmsCountabc123" wide ascii
		$2 = "loadSmsCountMethod" wide ascii
		$3 = "sentSms" wide ascii
		$4 = "getSentSms" wide ascii
		$5 = "maxSms" wide ascii

   	condition:
		all of them
}

rule FakeInst_v3
{
	meta:
        description = "FakeInst evidences v3"
		
	strings:
		$sa0 = "data.db" wide ascii
		$sa1 = "sms911.ru" wide ascii
		$sb0 = "agree.txt" wide ascii		
		$sb1 = "topfiless.com" wide ascii

   	condition:
		all of ($sa*) or all of ($sb*)
}

rule FakeInst_v4
{
	meta:
        description = "FakeInst evidences v4"
		
	strings:
		$1 = "android/telephony/gsm/SmsManager" wide ascii
		$2 = "getText123" wide ascii
		$3 = "setText123" wide ascii
		$4 = "text123" wide ascii

   	condition:
		all of them
}

rule FakeInst_domains
{
	meta:
        description = "FakeInst evidences domains"
		
	strings:
		$1 = "myfilies.net/?u=" wide ascii
		$2 = "m-love12.net/?aid=" wide ascii
		$3 = "androidosoft.ru/engine/download.php?id=" wide ascii
		$4 = "sellapis.ru/am/files/" wide ascii
		$5 = "myapkbox.cu.cc/market.php?t=" wide ascii
		$6 = "wap4mobi.ru/rools.html" wide ascii
		$7 = "filesmob.ru/getfile.php?fl=" wide ascii			
		
   	condition:
		1 of them
}
