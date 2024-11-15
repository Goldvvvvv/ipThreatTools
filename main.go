package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"time"
)

// 查询ip归属地
type ipinfo struct {
	IPType string `json:"type"`
	IPText string `json:"text"`
	Cnip   bool   `json:"cnip"`
}

// 查询ip归属地
type ipdata struct {
	Province string `json:"info1"`
	City     string `json:"info2"`
	Info3    string `json:"info3"`
	Isp      string `json:"isp"`
}

// 查询ip归属地
type ipInfoALL struct {
	Code   int    `json:"code"`
	Msg    string `json:"msg"`
	IpInfo ipinfo `json:"ipinfo"`
	IpData ipdata `json:"ipdata"`
}

// ip恶意威胁——域名恶意威胁查询
type Location struct {
	Country     string `json:"country"`
	Province    string `json:"province"`
	City        string `json:"city"`
	Lng         string `json:"lng"`
	Lat         string `json:"lat"`
	CountryCode string `json:"country_code"`
}

// ip恶意威胁查询
type Basic struct {
	Carrier  string   `json:"carrier"`
	Location Location `json:"location"`
}

// ip恶意威胁查询
type ASN struct {
	Rank   int    `json:"rank"`
	Info   string `json:"info"`
	Number int    `json:"number"`
}

// ip恶意威胁查询
type Judgment struct {
	Severity        string   `json:"severity"`
	Judgments       []string `json:"judgments"`
	TagsClasses     []string `json:"tags_classes"`
	Basic           Basic    `json:"basic"`
	ASN             ASN      `json:"asn"`
	Scene           string   `json:"scene"`
	ConfidenceLevel string   `json:"confidence_level"`
	IsMalicious     bool     `json:"is_malicious"`
	UpdateTime      string   `json:"update_time"`
}

// ip恶意威胁查询
type Data map[string]Judgment

// ip恶意威胁查询
type ThreatQueryResponse struct {
	Data         Data   `json:"data"`
	ResponseCode int    `json:"response_code"`
	VerboseMsg   string `json:"verbose_msg"`
}

// 恶意域名查询
type TagClass struct {
	TagsType string   `json:"tags_type"`
	Tags     []string `json:"tags"`
}

type IntelItem struct {
	Source     string     `json:"source"`
	FindTime   string     `json:"find_time"`
	Confidence int        `json:"confidence"`
	Expired    bool       `json:"expired"`
	IntelTypes []string   `json:"intel_types"`
	IntelTags  []TagClass `json:"intel_tags"`
}

type Intelligence struct {
	ThreatbookLab []IntelItem `json:"threatbook_lab"`
	XReward       []IntelItem `json:"x_reward"`
	OpenSource    []IntelItem `json:"open_source"`
}

type Sample struct {
	Sha256        string `json:"sha256"`
	ScanTime      string `json:"scan_time"`
	Ratio         string `json:"ratio"`
	MalwareType   string `json:"malware_type"`
	MalwareFamily string `json:"malware_family"`
}

type CurIP struct {
	IP       string   `json:"ip"`
	Carrier  string   `json:"carrier"`
	Location Location `json:"location"`
}
type WhoisInfo struct {
	RegistrarName     string `json:"registrar_name"`
	NameServer        string `json:"name_server"`
	RegistrantName    string `json:"registrant_name"`
	RegistrantEmail   string `json:"registrant_email"`
	RegistrantCompany string `json:"registrant_company"`
	RegistrantAddress string `json:"registrant_address"`
	RegistrantPhone   string `json:"registrant_phone"`
	Cdate             string `json:"cdate"`
	Udate             string `json:"udate"`
	Edate             string `json:"edate"`
	Alexa             string `json:"alexa"`
}

type RankInfo struct {
	GlobalRank int `json:"global_rank"`
}

type DomainData struct {
	Judgments     []string     `json:"judgments"`
	TagsClasses   []TagClass   `json:"tags_classes"`
	Intelligences Intelligence `json:"intelligences"`
	Samples       []Sample     `json:"samples"`
	CurIPs        []CurIP      `json:"cur_ips"`
	CurWhois      WhoisInfo    `json:"cur_whois"`
	Cas           interface{}  `json:"cas"`
	Rank          struct {
		AlexaRank    RankInfo `json:"alexa_rank"`
		UmbrellaRank RankInfo `json:"umbrella_rank"`
	} `json:"rank"`
	Categories struct {
		FirstCats  []string `json:"first_cats"`
		SecondCats string   `json:"second_cats"`
	} `json:"categories"`
	SumSubDomains string `json:"sum_sub_domains"`
	SumCurIPs     string `json:"sum_cur_ips"`
	Icp           struct {
		Domain      string `json:"domain"`
		Owner       string `json:"owner"`
		CompanyName string `json:"company_name"`
		CompanyType string `json:"company_type"`
		SiteLicense string `json:"site_license"`
		SiteName    string `json:"site_name"`
		MainPage    string `json:"main_page"`
		VerifyTime  string `json:"verify_time"`
	} `json:"icp"`
}

type DomainResponse struct {
	ResponseCode int                   `json:"response_code"`
	VerboseMsg   string                `json:"verbose_msg"`
	Domains      map[string]DomainData `json:"data"`
}

// 全局变量用于命令行参数
var ip = flag.String("ip", "", "Input Your Test IP")
var file = flag.String("file", "", "The path to the text file containing IP addresses, one per line")
var key = flag.String("key", "", "Please enter the key for the threatbook")
var domin = flag.String("domain", "", "Input Your Test domain")
var ipRegex = regexp.MustCompile(`^(?:\d{1,3}\.){3}\d{1,3}$`)
var domainRegex = regexp.MustCompile(`^(?:[a-zA-Z0-9]+(?:-[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,}$`)

// queryIP 查询单个 IP 地址
func queryIP(ip string) {
	url := fmt.Sprintf("https://api.vore.top/api/IPdata?ip=%s", ip)
	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("Query occurred an error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Read data from response error: %v\n", err)
		os.Exit(1)
	}

	var result ipInfoALL
	if err := json.Unmarshal(data, &result); err != nil {
		fmt.Printf("Error unmarshalling JSON: %v\n", err)
		os.Exit(1)
	}

	if result.Code == 200 {
		ipqueryprintFormattedResult(result)
	} else {
		fmt.Printf("Query failed with message: %s\n", result.Msg)
	}
}

// batchQuery 批量查询文件中的 IP 地址
func ipbatchQuery(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ip := scanner.Text()
		queryIP(ip)
		fmt.Println("--------------------------------------------------------------------------------------")
	}
	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading file: %v\n", err)
	}
}

// 单个ip威胁情报分析
func weibuqueryIPThreat(ip, key string) {
	url := fmt.Sprintf("https://api.threatbook.cn/v3/scene/ip_reputation?apikey=%s&resource=%s&lang=zh", key, ip)
	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("Query occurred an error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Read data from response error: %v\n", err)
		os.Exit(1)
	}
	var result ThreatQueryResponse
	if err := json.Unmarshal(data, &result); err != nil {
		fmt.Printf("Error unmarshalling JSON: %v\n", err)
		os.Exit(1)
	}
	if result.ResponseCode == 0 {
		printThreatQueryResponse(result)
	} else {
		fmt.Printf("Query failed with message: %s\n", result.VerboseMsg)
	}
}

// 单个域名威胁检测
func dominThreat(domain, key string) {

	url := fmt.Sprintf("https://api.threatbook.cn/v3/domain/query?apikey=%s&resource=%s&lang=zh", key, domain)
	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("Query occurred an error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Read data from response error: %v\n", err)
		os.Exit(1)
	}
	var result DomainResponse
	if err := json.Unmarshal(data, &result); err != nil {
		fmt.Printf("Error unmarshalling JSON: %v\n", err)
		os.Exit(1)
	}
	if result.ResponseCode == 0 {
		result.Print()
	} else {
		fmt.Printf("Query failed with message: %s\n", result.VerboseMsg)
	}

}

func batchQueryAll(filename, key string) {
	file, err := os.Open(filename)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// 检查是否是 IP
		if ipRegex.MatchString(line) {
			weibuqueryIPThreat(line, key) // 调用 IP 查询
		} else if domainRegex.MatchString(line) {
			dominThreat(line, key) // 调用域名查询
		} else {
			fmt.Printf("Unrecognized format: %s\n", line)
		}
		fmt.Println("-----------------------------------------------------------------------------")
		time.Sleep(time.Second * 2)
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading file: %v\n", err)
	}
}

// 格式化并打印ip查询结果
func ipqueryprintFormattedResult(result ipInfoALL) {
	fmt.Println("Query successful!")
	fmt.Printf("IP Information:\n")
	fmt.Printf("  Type: %s\n", result.IpInfo.IPType)
	fmt.Printf("  Text: %s\n", result.IpInfo.IPText)
	fmt.Printf("  Is CN IP: %v\n", result.IpInfo.Cnip)
	fmt.Printf("Data Information:\n")
	fmt.Printf("  Province: %s\n", result.IpData.Province)
	fmt.Printf("  City: %s\n", result.IpData.City)
	fmt.Printf("  ISP: %s\n", result.IpData.Isp)
}

// 格式化并打印ip威胁查询结果
func printThreatQueryResponse(response ThreatQueryResponse) {
	fmt.Println("Verbose Message:", response.VerboseMsg)
	// fmt.Println("Response Code:", response.ResponseCode)
	if response.ResponseCode == 0 {
		fmt.Println("Threat Data:")
		for ip, threatInfo := range response.Data {
			fmt.Printf("IP: %s\n", ip)
			fmt.Printf("  Severity: %s\n", threatInfo.Severity)
			fmt.Printf("  Judgments: %v\n", threatInfo.Judgments)
			fmt.Printf("  Basic Info: {Carrier: %s, Location: %+v}\n", threatInfo.Basic.Carrier, threatInfo.Basic.Location)
			fmt.Printf("  ASN Info: {Rank: %d, Info: %s, Number: %d}\n", threatInfo.ASN.Rank, threatInfo.ASN.Info, threatInfo.ASN.Number)
			fmt.Printf("  Scene: %s\n", threatInfo.Scene)
			fmt.Printf("  Confidence Level: %s\n", threatInfo.ConfidenceLevel)
			fmt.Printf("  Is Malicious: %t\n", threatInfo.IsMalicious)
			fmt.Printf("  Update Time: %s\n", threatInfo.UpdateTime)
			fmt.Println("-----------------------------------------------------------------------------------")
		}
	} else {
		fmt.Println("Failed to retrieve data.")
	}
}

// 格式化并打印域名威胁查询结果
func (r DomainResponse) Print() {
	fmt.Println("Verbose Message:", r.VerboseMsg)
	fmt.Println("Response Code:", r.ResponseCode)
	for domain, data := range r.Domains {
		fmt.Printf("Domain: %s\n", domain)
		fmt.Println("  Judgments:", data.Judgments)
		fmt.Println("  Tags Classes:", data.TagsClasses)
		fmt.Println("  Intelligences:")
		for _, intel := range data.Intelligences.ThreatbookLab {
			fmt.Printf("    - Source: %s, Find Time: %s, Confidence: %d, Expired: %t\n",
				intel.Source, intel.FindTime, intel.Confidence, intel.Expired)
		}
		fmt.Println("  Samples:")
		for _, sample := range data.Samples {
			fmt.Printf("    - SHA256: %s, Scan Time: %s, Ratio: %s\n", sample.Sha256, sample.ScanTime, sample.Ratio)
		}
		fmt.Println("  Current IPs:")
		for _, ip := range data.CurIPs {
			fmt.Printf("    - IP: %s, Carrier: %s, Location: %+v\n", ip.IP, ip.Carrier, ip.Location)
		}
		fmt.Printf("  Current WHOIS Info: %+v\n", data.CurWhois)
		fmt.Println("-----------------------------------------------------------------------------------------------------")
	}
}

// main 函数解析命令行参数并调用相应的查询函数
func main() {
	flag.Parse()
	switch {
	// 查询单个 IP 信息
	case *ip != "" && *key == "" && *domin == "":
		queryIP(*ip)

	// 批量查询 IP 信息
	case *file != "" && *key == "" && *domin == "":
		ipbatchQuery(*file)

	// 查询单个 IP 威胁情报
	case *ip != "" && *key != "" && *domin == "":
		weibuqueryIPThreat(*ip, *key)

	// 批量查询 IP 威胁情报
	case *file != "" && *key != "" && *domin == "":
		batchQueryAll(*file, *key)

	// 查询单个域名威胁情报
	case *domin != "" && *file == "" && *key != "":
		dominThreat(*domin, *key)

	// 批量查询域名威胁情报
	case *domin == "" && *file != "" && *key != "":
		batchQueryAll(*file, *key)

	default:
		fmt.Println("Find the IP home, use the -ip command, and conduct batch query with -file")
		fmt.Println("eg: ./ipThreatTools -ip 192.168.1.1 or ./ipThreatTools -file 1.txt")
		fmt.Println("Analyze the IP threat level, use -ip and batch query with -file, -key (threatbook's key)")
		fmt.Println("eg: ./ipThreatTools -ip 192.168.1.1 -key [threatbook's key] or ./ipThreatTools -file 1.txt -key [threatbook's key]")
		fmt.Println("Analyze the domain threat level, use -domain and -key to query")
		fmt.Println("eg: ./ipThreatTools -domain baidu.com -key [threatbook's key] or ./ipThreatTools -file 1.txt -key [threatbook's key]")
		flag.PrintDefaults()
	}

}
