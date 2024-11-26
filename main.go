package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/Ullaakut/nmap/v3"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func containsString(slicePtr *[]string, target string) bool {
	if slicePtr == nil {
		return false
	}
	slice := *slicePtr
	for _, item := range slice {
		if item == target {
			return true
		}
	}
	return false
}

func nmapStart(domain string, ports string, NewScanTypeList []string, MyParameter string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	var portList []string
	var scanner *nmap.Scanner
	var err error
	defer cancel()

	if MyParameter == "" {
		scanner, err = nmap.NewScanner(
			ctx,
			nmap.WithCustomArguments(NewScanTypeList...),
			nmap.WithTargets(domain),
			nmap.WithPorts(ports),
		)
	} else {
		scanner, err = nmap.NewScanner(
			ctx,
			nmap.WithCustomArguments(NewScanTypeList...),
			nmap.WithCustomArguments(MyParameter),
			nmap.WithTargets(domain),
			nmap.WithPorts(ports),
		)
	}

	if err != nil {
		log.Printf("Error in creating the scan. %v", err)
		return nil, err
	}

	result, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		log.Printf("Warning: %s\n", *warnings) // Warnings are non-critical errors from nmap.
		if containsString(warnings, "so 0 hosts scanned") {
			tmp := []string{"domain failed to resolve"}
			return tmp, nil
		}
		return *warnings, nil

	}
	if err != nil {
		return nil, err
	}

	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			portList = append(portList, "")
		}
		fmt.Printf("Host %q:\n", host.Addresses[0])
		portList = append(portList, fmt.Sprintf("%s Confidence level:%d%%", host.OS.Matches[0].Name, host.OS.Matches[0].Accuracy))
		for _, port := range host.Ports {
			fmt.Printf("\tPort %d/%s %s %s \n", port.ID, port.Protocol, port.State, port.Service.Name)
			portList = append(portList, fmt.Sprintf("%d/%s %s %s", port.ID, port.Protocol, port.State, port.Service.Name))
		}
	}
	return portList, nil
}

func reStartNmap(target string, num *int, ports string, NewScanTypeList []string, MyParameter string) ([]string, error) {
	*num++
	fmt.Printf("%s The %d scan is in progress.\n", target, num)
	nmapPorts, err := nmapStart(target, ports, NewScanTypeList, MyParameter)
	return nmapPorts, err
}

// domainInitScan函数执行对单个域名的rustscan和nmap扫描
func domainInitScan(target string, ports string, NewScanTypeList []string, MyParameter string) map[string][]string {
	var nmapPorts []string
	var resultMap = make(map[string][]string)
	var killedErr error
	var err error
	var num int
	maxRetries := 3
	killedErr = errors.New("signal: killed")
	for i := 0; i < maxRetries; i++ {
		nmapPorts, err = nmapStart(target, ports, NewScanTypeList, MyParameter)
		if err != nil && errors.Is(err, killedErr) {
			nmapPorts, err = reStartNmap(target, &num, ports, NewScanTypeList, MyParameter)
		} else if err != nil && nmapPorts != nil {
			resultMap[target] = []string{strings.Join(nmapPorts, ",")}
			return resultMap
		} else if err == nil {
			resultMap[target] = []string{strings.Join(nmapPorts, ",")}
			return resultMap
		}
	}
	errData := fmt.Sprintf("error:%s", err)
	fmt.Println(target, errData)
	resultMap[target] = []string{errData}
	return resultMap

}
func readFile(hostsfile string) []string {
	hostsList := []string{}

	file, err := os.Open(hostsfile)
	if err != nil {
		log.Fatalf("Error opening the file. %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := scanner.Text()
		if domain != "" {
			hostsList = append(hostsList, domain)
		}
	}

	if err = scanner.Err(); err != nil {
		log.Fatalf("Error reading the file.%v", err)
	}
	return hostsList
}

func saveJson(results chan map[string][]string, saveFilename string) {
	var wg sync.WaitGroup
	// 这里省略了填充results通道的并发任务部分代码，假设已经完成
	fmt.Println("All targets：", len(results))
	fmt.Println("Writing to the JSON file...")
	// 创建一个文件用于写入结果
	file, err := os.Create(saveFilename)
	if err != nil {
		fmt.Println("Error creating the file.", err)
		return
	}
	defer file.Close()
	wg.Add(1)
	// 从通道中读取结果并写入文件
	go func() {

		for result := range results {
			if len(result) == 0 {
				continue
			}
			// 将map结果转换为JSON格式字符串
			jsonResult, err := json.Marshal(result)
			if err != nil {
				fmt.Println("Error occurred during JSON format conversion.", err)
				continue
			}

			// 将JSON格式的结果写入文件
			_, err = file.Write(jsonResult)
			if err != nil {
				fmt.Println("Error writing to the file.", err)
				continue
			}

			// 写入换行符，使每个结果在文件中换行显示
			_, err = file.Write([]byte("\n"))
			if err != nil {
				fmt.Println("Error occurred when writing the newline character.", err)
				continue
			}
		}
		defer wg.Done()
	}()

	// 等待所有结果都被读取并写入文件
	wg.Wait()

	fmt.Println("The results have been successfully written into the file.")
}
func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
func compareIPs(startIP, endIP net.IP) bool {
	return bytes.Compare(startIP, endIP) < 0
}

func expandIPRange(ipRange string, ips *[]string) ([]string, error) {

	var startIP net.IP
	var endIP net.IP

	if strings.Contains(ipRange, "-") {
		startIP = net.ParseIP(ipRange[:strings.Index(ipRange, "-")])

		endIP = net.ParseIP(ipRange[strings.Index(ipRange, "-")+1:])

		for startIP := startIP; startIP != nil && startIP.Equal(endIP) || compareIPs(startIP, endIP); incIP(startIP) {
			*ips = append(*ips, startIP.String())
		}
		return *ips, nil
	} else if strings.Contains(ipRange, "/") {
		// 处理CIDR表示法（如192.168.1.0/24）
		ip, ipnet, err := net.ParseCIDR(ipRange)
		if err != nil {
			return nil, err
		}

		// 遍历CIDR范围内的所有IP地址
		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
			*ips = append(*ips, ip.String())
		}

		return *ips, nil
	} else {
		// 如果既不包含 - 也不包含 /，则认为是单个IP地址，直接添加到列表
		*ips = append(*ips, ipRange)
		return *ips, nil
	}
}

func getDataList(ipDataList *[]string, ips []string) {
	var err error
	for _, ipRange := range ips {
		ips, err = expandIPRange(ipRange, ipDataList)
		if err != nil {
			fmt.Println("Error:", err)
			continue
		}
		fmt.Println(ips)
	}
}

func getTerminal() (uint, []string, string, string, string, []string, string) {
	// 定义一个变量来存储协程数量
	var maxGoroutineNum uint
	var ips string
	var ports string
	var ipsList []string

	var ScanType string
	var readFileName string
	var saveFileName string
	var MyParameter string
	// 将命令行参数与变量绑定，"goroutine-num"是命令行参数的名称，"20"是默认值，"设置协程数量"是帮助信息
	flag.UintVar(&maxGoroutineNum, "go", 20, "设置协程数量")
	flag.StringVar(&ScanType, "type", "-sS", "设置扫描方式，当多个参数时：sS,Pn")
	flag.StringVar(&ips, "r", "", "接受ip格式：192.168.0.0/16 or 192.168.187.1-192.168.187.10 or 192.168.187.1,192.168.187.2 ...")
	flag.StringVar(&ports, "p", "22,23,25,80,443,1433,3389,8080", "指定端口")
	flag.StringVar(&readFileName, "file", "hosts.txt", "指定读取目标的文件名")
	flag.StringVar(&saveFileName, "ho", "scan_results.json", "指定保存的文件名")
	flag.StringVar(&MyParameter, "m", "", "自定义参数使用,号分割")
	// 解析命令行参数
	flag.Parse()
	var NewScanTypeList []string
	if strings.Contains(ScanType, ",") {
		ScanList := strings.Split(ScanType, ",")
		for _, item := range ScanList {
			NewScanTypeList = append(NewScanTypeList, "-"+item)
		}
	}

	if ips != "" || strings.Contains(ips, ",") {
		for _, data := range strings.Split(ips, ",") {
			ipsList = append(ipsList, data)
		}
	}
	if strings.Contains(saveFileName, "/") {
		filePath := strings.Split(saveFileName, "/")
		dirPath := filepath.Join(filePath[:len(filePath)-1]...)

		// 判断路径是否存在
		if _, err := os.Stat(dirPath); os.IsNotExist(err) {
			// If the directory does not exist, create the path
			err = os.MkdirAll(dirPath, os.ModePerm)
			if err != nil {
				fmt.Printf("Failed to create the path: %v\n", err)
				return 0, nil, "", "", "", nil, ""
			}
			fmt.Printf("The path %s has been successfully created\n", dirPath)
		} else if err != nil {
			fmt.Printf("An error occurred while getting the path status: %v\n", err)
			return 0, nil, "", "", "", nil, ""
		} else {
			fmt.Printf("The path %s exists, starting the scan normally\n", dirPath)
		}
	}
	return maxGoroutineNum, ipsList, readFileName, saveFileName, ports, NewScanTypeList, MyParameter
}

func startNmap(hostsList *[]string, maxConcurrent uint, saveFilename string, ports string, NewScanTypeList []string, MyParameter string) {

	fmt.Printf("Domain num ：%d\n", len(*hostsList))

	fmt.Printf("Specify the maximum number of threads to run as：%d\n", maxConcurrent)
	var wg sync.WaitGroup
	results := make(chan map[string][]string, len(*hostsList))
	result := make(map[string][]string, len(*hostsList))
	sem := make(chan struct{}, maxConcurrent)
	// 该通道用于接收任务完成的信号
	taskDoneChan := make(chan struct{})

	// 记录总任务数
	totalTasks := len(*hostsList)
	// 已完成任务数
	completedTasks := 0

	for _, doamin := range *hostsList {
		wg.Add(1)
		go func(doamin string) {
			defer wg.Done()
			sem <- struct{}{}        // 获取一个许可证
			defer func() { <-sem }() // 释放许可证
			result = domainInitScan(doamin, ports, NewScanTypeList, MyParameter)
			results <- result
			completedTasks++
			// 计算并显示任务完成进度
			progress := float64(completedTasks) / float64(totalTasks) * 100
			fmt.Printf("Task completion progress: %.2f%%\n", progress)
		}(doamin)
	}
	// 用于实时显示已用时间的协程

	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				currentTime := time.Now()
				fmt.Printf("Real-time: %v Working hard on scanning~~\n", currentTime)
			case <-taskDoneChan:
				return
			}
		}
	}()
	fmt.Println("Waiting for all tasks to complete...")

	wg.Wait()
	close(results)
	close(taskDoneChan)
	saveJson(results, saveFilename)
	return
}

func main() {

	var hostsList []string
	startTime := time.Now()
	maxConcurrent, ipsList, fileName, saveFilename, ports, NewScanTypeList, MyParameter := getTerminal()
	if maxConcurrent == 0 && ipsList == nil && fileName == "" && saveFilename == "" && ports == "" && NewScanTypeList == nil {
		return
	}
	if len(ipsList) == 0 {
		hostsList = readFile(fileName)
	} else {
		getDataList(&hostsList, ipsList)
	}

	startNmap(&hostsList, maxConcurrent, saveFilename, ports, NewScanTypeList, MyParameter)

	endTime := time.Now()
	resTime := endTime.Sub(startTime)
	hours := int(resTime.Hours())
	minutes := int(resTime.Minutes()) % 60
	seconds := int(resTime.Seconds()) % 60
	milliseconds := int(resTime.Milliseconds()) % 1000

	fmt.Printf("The total running time of the program is: %02d:%02d:%02d.%03d\n", hours, minutes, seconds, milliseconds)
}
