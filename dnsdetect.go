package main

import (
	_ "encoding/hex"
	"flag"
	"fmt"
	"log"
	_ "net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	intface    string
	filename   string
	bpf_filter string

	requestFrequency  map[string]int
	responseFrequency map[string]int
	ipList            map[string]string
	timestamp         map[string]string
)

type DnsMsg struct {
	Timestamp       string
	SourceIP        string
	DestinationIP   string
	DnsQuery        string
	DnsAnswer       []string
	DnsAnswerTTL    []string
	NumberOfAnswers string
	DnsResponseCode string
	DnsId           string
}

var (
	InetAddr string
	SrcIP    string
	DstIP    string
	SrcPort  string
	DstPort  string
)

func main() {

	//Getting command line inputs
	_ = bpf_filter
	flag.StringVar(&intface, "i", "No interface provided", "your interface in promiscuous mode")
	flag.StringVar(&filename, "r", "no file provided", "trace file")
	flag.Parse()
	bpf_filter = "nil"
	argsWithoutProg := os.Args[1:]

	//if there are more than one arguments - to extract the "bpf filter"
	if len(argsWithoutProg) != 0 {
		if (os.Args[len(argsWithoutProg)-1] != "-i") && (os.Args[len(argsWithoutProg)-1] != "-r") {
			bpf_filter = os.Args[len(argsWithoutProg)]
		}
	}

	/*

		Either opencapture or capture from trace file

		For open capture, if the network interface is unspecified,
		devices in the network is found using FindAllDevs - first NIC is captured and used
	*/
	if bpf_filter == "nil" {
		bpf_filter = "udp and port 53"
	}

	requestFrequency = make(map[string]int)
	responseFrequency = make(map[string]int)
	timestamp = make(map[string]string)
	ipList = make(map[string]string)

	if filename == "no file provided" {
		if intface == "No interface provided" {
			findDevices()
		} else {
			liveCapture()
		}
	} else {
		readFile()
	}

}

//Ascertaining default network interface when input is not given for the Network interface
func findDevices() {
	// Find all devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	intface = devices[0].Name
	liveCapture()
}

func readFile() {
	var (
		handle *pcap.Handle
		err    error
	)

	handle, err = pcap.OpenOffline(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	//Setting BPF Filter
	if bpf_filter != "nil" {
		err = handle.SetBPFFilter(bpf_filter)
		if err != nil {
			fmt.Printf("---- Please enter BPF filter in accurate BPF syntax ----\n")
			log.Fatal(err)
		}
	}

	// Loop through packets in file
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		processPacket(packet)
	}

}

func liveCapture() {

	fmt.Print("I AM IN LIVE CAPTURE \n")
	fmt.Print("\n")
	var (
		device       string = intface
		snapshot_len int32  = 1024
		promiscuous  bool   = true
		err          error
		timeout      time.Duration = 1 * time.Second
		handle       *pcap.Handle
	)

	// Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	//Setting BPF Filter

	if bpf_filter != "nil" {
		err = handle.SetBPFFilter(bpf_filter)
		if err != nil {
			fmt.Printf("---- Please enter BPF filter in accurate BPF syntax ----\n")
			log.Fatal(err)
		}
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		processPacket(packet)
	}

}

func processPacket(packet gopacket.Packet) {

	var key string

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		SrcPort = udp.SrcPort.String()
	}
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		SrcIP = ip.SrcIP.String()
		DstIP = ip.DstIP.String()
	}
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer != nil {
		dns, _ := dnsLayer.(*layers.DNS)
		dnsId := int(dns.ID)
		dnsResponseCode := int(dns.ResponseCode)
		dnsANCount := int(dns.ANCount)

		var dnsQuer string
		for _, dnsQuestion := range dns.Questions {
			dnsQuer = string(dnsQuestion.Name)
		}
		key = strconv.Itoa(dnsId) + " " + dnsQuer
		captureInfo := packet.Metadata().CaptureInfo
		timeTemp := captureInfo.Timestamp.Unix()
		if (dnsANCount == 0 && dnsResponseCode > 0) || (dnsANCount > 0) { //DNS Response Block

			responseFrequency[key]++ //Increasing frequency of specifc Txn ID - Hostname pair in responses
			if dnsANCount > 0 {
				for _, dnsAnswer := range dns.Answers {
					if dnsAnswer.IP.String() != "<nil>" {
						ipList[key] = ipList[key] + dnsAnswer.IP.String() + " "
					}
				}
				ipList[key] = ipList[key] + "|"
				timestamp[key] = strconv.Itoa(int(timeTemp)) + "|"
			}

		} else { // DNS Query block
			requestFrequency[key]++
			timestamp[key] = strconv.Itoa(int(timeTemp)) + "|"
		}
		//Common area here for both Request and Response
		checkForSpoofing(key)
	}
}

func checkForSpoofing(key string) {
	temp := strings.Split(key, " ")
	tId := temp[0]
	domainName := temp[1]

	if responseFrequency[key] > requestFrequency[key] {
		timeSplit := strings.Split(timestamp[key], "|")
		firstPacketTime, err1 := strconv.Atoi(timeSplit[0])
		if err1 != nil {
			fmt.Printf("Formatting error with early timestamp \n")
		}
		latestPacketTime, err2 := strconv.Atoi(timeSplit[len(timeSplit)-2])
		if err2 != nil {
			fmt.Printf("Formatting error with late timestamp \n")
		}

		if latestPacketTime-firstPacketTime < 5 {
			fmt.Print("\n")
			dt := time.Now()
			fmt.Print(dt.Format("01-02-2006 15:04:05.000000"))
			fmt.Println(" DNS poisoning attempt")
			fmt.Print("\n")

			fmt.Print("TXID 0x")
			val, errConv := strconv.Atoi(tId)
			if errConv != nil {
				fmt.Printf("Formatting error with id \n")
			}
			fmt.Print(strconv.FormatInt(int64(val), 16))
			fmt.Print(" Request ")
			fmt.Print(domainName)
			fmt.Print("\n")

			targetIps := strings.Split(ipList[key], "|")

			for i := 0; i < len(targetIps)-1; i++ {
				fmt.Printf("Answer %d", i+1)
				fmt.Printf("[ %s]", targetIps[i])
				fmt.Print("\n")
			}
			fmt.Print("\n")
		}
	}

}
