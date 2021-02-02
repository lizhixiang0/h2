/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: asrabon
    Rule name: Chrysaor
    Rule id: 4899
    Created at: 2018-09-21 14:26:17
    Updated at: 2018-09-21 14:26:41
    
    Rating: #0
    Total detections: 46
*/

rule ade8bef0ac29fa363fc9afd958af0074478aef650adeb0318517b48bd996d5d5 {
   meta:
      description = "chrysaor - file ade8bef0ac29fa363fc9afd958af0074478aef650adeb0318517b48bd996d5d5"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2018-09-21"
      hash1 = "ade8bef0ac29fa363fc9afd958af0074478aef650adeb0318517b48bd996d5d5"
   strings:
      $s1 = "res/raw/cmdshellPK" fullword ascii
      $s2 = "res/raw/cmdshell" fullword ascii
      $s3 = "CHANGELOGPK" fullword ascii
      $s4 = "com.network.android" fullword wide
      $s5 = "org/eclipse/paho/client/mqttv3/internal/nls/messages_ja.propertiesPK" fullword ascii
      $s6 = "org/eclipse/paho/client/mqttv3/internal/nls/messages.propertiesPK" fullword ascii
      $s7 = "org/eclipse/paho/client/mqttv3/internal/nls/messages_ko.properties" fullword ascii
      $s8 = "org/eclipse/paho/client/mqttv3/internal/nls/messages_cs.propertiesmTMO" fullword ascii
      $s9 = "org/eclipse/paho/client/mqttv3/internal/nls/messages_ru.properties" fullword ascii
      $s10 = "org/eclipse/paho/client/mqttv3/internal/nls/messages_pt_BR.propertiesPK" fullword ascii
      $s11 = "org/eclipse/paho/client/mqttv3/internal/nls/messages_zh_CN.properties" fullword ascii
      $s12 = "org/eclipse/paho/client/mqttv3/internal/nls/messages_cs.propertiesPK" fullword ascii
      $s13 = "org/eclipse/paho/client/mqttv3/internal/nls/messages.properties]R" fullword ascii
      $s14 = "org/eclipse/paho/client/mqttv3/internal/nls/messages_es.properties]S" fullword ascii
      $s15 = "org/eclipse/paho/client/mqttv3/internal/nls/messages_ko.propertiesPK" fullword ascii
      $s16 = "org/eclipse/paho/client/mqttv3/internal/nls/messages_es.propertiesPK" fullword ascii
      $s17 = "org/eclipse/paho/client/mqttv3/internal/nls/messages_pl.properties" fullword ascii
      $s18 = "org/eclipse/paho/client/mqttv3/internal/nls/messages_ja.properties" fullword ascii
      $s19 = "org/eclipse/paho/client/mqttv3/internal/nls/messages_pt_BR.propertiesmS" fullword ascii
      $s20 = "org/eclipse/paho/client/mqttv3/internal/nls/messages_pl.propertiesPK" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 800KB and
      8 of them
}
