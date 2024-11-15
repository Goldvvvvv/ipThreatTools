用法：./ipThreatTools  或者  ipthreattools.exe [选项]
 ![image](https://github.com/user-attachments/assets/af049c21-dffd-4cb9-8af9-015f8c523d45)

选项：
  -ip <IP地址>        查询单个IP地址的信息。
  -file <文件路径>     包含IP地址或域名的文本文件路径，每行一个。
  -key <API密钥>       您的威胁情报服务API密钥。
  -domin <域名>        查询单个域名的威胁情报。
示例：
  查询单个IP地址的信息：
    ./ipThreatTools -ip 192.168.1.1

  从文件批量查询IP地址信息：
    ./ipThreatTools -file ips.txt

  使用您的API密钥分析单个IP地址的威胁等级：
    ./ipThreatTools -ip 192.168.1.1 -key [您的_api密钥]

  使用您的API密钥分析多个IP地址的威胁等级：
    ./ipThreatTools -file ips.txt -key [您的_api密钥]

  查询单个域名的威胁情报：
    ./ipThreatTools -domin example.com -key [您的_api密钥]


  从文件批量查询域名威胁情报：
    ./ipThreatTools -file domains.txt -key [您的_api密钥]
