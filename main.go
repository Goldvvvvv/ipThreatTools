package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
)

// 定义结构体以匹配 JSON 响应
type ipinfo struct {
	IPType string `json:"type"`
	IPText string `json:"text"`
	Cnip   bool   `json:"cnip"`
}

type ipdata struct {
	Province string `json:"info1"`
	City     string `json:"info2"`
	Info3    string `json:"info3"`
	Isp      string `json:"isp"`
}

type ipInfoALL struct {
	Code   int    `json:"code"`
	Msg    string `json:"msg"`
	IpInfo ipinfo `json:"ipinfo"`
	IpData ipdata `json:"ipdata"`
}
type Location struct {
	Country     string `json:"country"`
	Province    string `json:"province"`
	City        string `json:"city"`
	Lng         string `json:"lng"`
	Lat         string `json:"lat"`
	CountryCode string `json:"country_code"`
}

type Basic struct {
	Carrier  string   `json:"carrier"`
	Location Location `json:"location"`
}

type ASN struct {
	Rank   int    `json:"rank"`
	Info   string `json:"info"`
	Number int    `json:"number"`
}

type ThreatInfo struct {
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

type ThreatData struct {
	Data map[string]ThreatInfo `json:"data"`
}

type ThreatQueryResponse struct {
	ResponseCode int        `json:"response_code"`
	VerboseMsg   string     `json:"verbose_msg"`
	Data         ThreatData `json:"data"`
}

// 全局变量用于命令行参数
var ip = flag.String("ip", "", "Input Your Test IP")
var file = flag.String("file", "", "The path to the text file containing IP addresses, one per line")
var key = flag.String("key", "", "Please enter the key for the threatbook")

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
func batchQuery(filename string) {
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
	if result.ResponseCode == 200 {
		printThreatQueryResponse(result)
	} else {
		fmt.Printf("Query failed with message: %s\n", result.VerboseMsg)
	}
}

// 多个ip威胁情报分析
func queryIPThreat(filename, key string) {
	file, err := os.Open(filename)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ip := scanner.Text()
		weibuqueryIPThreat(ip, key)
		fmt.Println("-----------------------------------------------------------------------------")
	}
	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading file: %v\n", err)
	}
}

// printFormattedResult 格式化并打印查询结果
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

func printThreatQueryResponse(response ThreatQueryResponse) {
	fmt.Printf("Response Code: %d\n", response.ResponseCode)
	fmt.Println("Verbose Message:")
	fmt.Println(response.VerboseMsg)
	fmt.Println("Data:")
	for key, info := range response.Data.Data {
		fmt.Printf("  ID: %s\n", key)
		fmt.Printf("  Severity: %s\n", info.Severity)
		fmt.Println("  Judgments:")
		for _, judgment := range info.Judgments {
			fmt.Printf("    - %s\n", judgment)
		}
		fmt.Println("  Tags Classes:")
		for _, tag := range info.TagsClasses {
			fmt.Printf("    - %s\n", tag)
		}
		fmt.Println("  Basic Info:")
		fmt.Printf("    Carrier: %s\n", info.Basic.Carrier)
		fmt.Printf("    Location: %+v\n", info.Basic.Location)
		fmt.Printf("    ASN Info: %+v\n", info.ASN)
		fmt.Printf("    Scene: %s\n", info.Scene)
		fmt.Printf("    Confidence Level: %s\n", info.ConfidenceLevel)
		fmt.Printf("    Is Malicious: %t\n", info.IsMalicious)
		fmt.Printf("    Update Time: %s\n", info.UpdateTime)
		fmt.Println("----------")
	}
}

// main 函数解析命令行参数并调用相应的查询函数
func main() {
	flag.Parse()
	if *ip != "" && *key == "" {
		queryIP(*ip)
	} else if *file != "" && *key == "" {
		batchQuery(*file)
	} else if *ip != "" && *key != "" {
		weibuqueryIPThreat(*ip, *key)
	} else if *file != "" && *key != "" {
		queryIPThreat(*file, *key)
	} else {
		fmt.Println("Please provide an IP address with the -ip flag or a file with the -file flag")
		flag.PrintDefaults()
	}
}
