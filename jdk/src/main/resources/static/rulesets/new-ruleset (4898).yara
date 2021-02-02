/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asrabon
    Rule name: New Ruleset
    Rule id: 4898
    Created at: 2018-09-21 14:06:14
    Updated at: 2018-09-21 14:07:15
    
    Rating: #0
    Total detections: 26
*/

rule SpyHuman {
   meta:
      description = "spyhuman - from files Secure Service 10.11.apk, Secure Service 10.6.apk, Secure Service 10.5.apk, Secure Service 10.4.apk, Secure Service 10.1.apk, Secure Service 10.8.apk, Secure Service 10.17.apk, Secure Service 10.3.apk, Secure Service 10.0.apk, Secure Service 10.2.apk, Secure Service 10.10.apk, Secure Service 10.16.apk, Secure Service 10.15.apk, Secure Service 10.14.apk, Secure Service 10.7.apk, Secure Service 10.9.apk"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2018-09-21"
      hash1 = "0602b0039b80d539d0218aa3572034cc98cf6c9eec160299d8acdb3867c66991"
      hash2 = "ab55fa9a540d6c6513fb46d410bda6d53dff9ce13ebe9d1cc9b51930c098050f"
      hash3 = "5498c8dc93293991c1799b2d7f1849a90d333a694d862a47960f2ec4c854d0d9"
      hash4 = "fc54f35982137778b414fc8bba37d35b781c57ac9a65ff8419aabc5b036495cc"
      hash5 = "81605a37523525879ce7c1dd5a90645983aaf0030c7d05192a0f6e1584d25828"
      hash6 = "df0a702836a645a14bb0ebe9a7206b0c9019282d5d08b0c7224adf6398e6feda"
      hash7 = "a636de7408823cd71856c15f41a3f72e994ffb75adb197a112f92c47996be457"
      hash8 = "5c9aef9eed594101f84e7e0117c7929f5b5c579dde52497018d61f4bb4a121c8"
      hash9 = "4702cd8466e4103d36a8583ba522d729dd657ae0e3580c43d5823b32ce8182ad"
      hash10 = "612704da90c579b69d7d8395d4d2f257922333c6a6dcbe2d1dd59a6ced5f32f6"
      hash11 = "96a07428171d06fce2e5941027dd6087bf4e6a30efbbd4be69e45d99359e64dc"
      hash12 = "23b4351b716e7dbede06c467081663a57bec5dbdbcd4a90bc7b01eeaf5f2e246"
      hash13 = "02787e2002e3721723abd42073031c884da5f76ec715c9f70c6656ccfd481bfe"
      hash14 = "825f7ba60108af936aa73b40862b33ac6d8a27ce7f1117feacf35b45b0a6e292"
      hash15 = "56c5129b7a151c86a12c8808b0dc7c41e32212362ca6c053b4fe6415a9621ed1"
      hash16 = "43d58b421de1e558e9a4b01210d9a15d9a6029762ea574d7a1236dcfe37be5fc"
   strings:
      $s1 = "HH547604601335-t88lg026s1s4ukkcvp1hijjv3jb0qulo.apps.googleusercontent.com" fullword ascii
      $s2 = "BBTarget Device is not registered. Please login or register account." fullword ascii
      $s3 = "Please click button Register to create one account of spyhuman.com. Else if you have an account then click button Login to assig" ascii
      $s4 = "Please click button Register to create one account of spyhuman.com. Else if you have an account then click button Login to assig" ascii
      $s5 = "vvYou can monitor this device from your computer or iPhone/iPad or other mobile phones by visiting website spyhuman.com." fullword ascii
      $s6 = "www.spyhuman.com" fullword ascii
      $s7 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c014 79.156797, 2014/08/" ascii
      $s8 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c014 79.156797, 2014/08/" ascii
      $s9 = "DDPlease wait to retrieve information from server (site spyhuman.com)." fullword ascii
      $s10 = "<<Register your device with spyhuman.com and start monitoring." fullword ascii
      $s11 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c014 79.156797, 2014/08/" ascii
      $s12 = "22Base.Widget.AppCompat.Button.ButtonBar.AlertDialog" fullword ascii
      $s13 = "##safesecureservice-702df.appspot.com" fullword ascii
      $s14 = "..https://safesecureservice-702df.firebaseio.com" fullword ascii
      $s15 = "00Base.Widget.AppCompat.CompoundButton.RadioButton" fullword ascii
      $s16 = "11RtlOverlay.Widget.AppCompat.Search.DropDown.Icon1" fullword ascii
      $s17 = "11RtlOverlay.Widget.AppCompat.Search.DropDown.Icon2" fullword ascii
      $s18 = "00RtlOverlay.Widget.AppCompat.Search.DropDown.Text" fullword ascii
      $s19 = "11RtlOverlay.Widget.AppCompat.Search.DropDown.Query" fullword ascii
      $s20 = "Control Panel: www.spyhuman.com" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 6000KB and ( 8 of them )
      ) or ( all of them )
}
