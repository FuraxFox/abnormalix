
package main

import (
	"os"
    "fmt"                   // Import the fmt package to print messages to the console.
    "log"                   // Import the log package to log errors to the console.
    "github.com/google/gopacket/pcap" // Import the pcap package to capture packets.
    "github.com/google/gopacket" // Import the gopacket package to decode packets.
    "github.com/google/gopacket/layers" // Import the layers package to access the various network layers.
	"encoding/binary"
	"net"
)

type NetworkProfileMetric interface{
	Differs ( m *NetworkProfileMetric ) (string,bool)
	Update(p *gopacket.Packet )
	Dump() string
}

type PacketCounter struct {
	PacketsCount int
	SizeTotal    int

}
func (c *PacketCounter) Update(p *gopacket.Packet ) {
	c.PacketsCount++
	c.SizeTotal += binary.Size(p.Data())
}

// Level 2 communication profile
type L2ComMetricCounter struct {
	history map[string]map[string] int64
	counter PacketCounter
}

func (m*L2ComMetricCounter)Update(p gopacket.Packet) {
    ethLayer := p.Layer(layers.LayerTypeEthernet)
    if ethLayer != nil {
        ethPacket, _ := ethLayer.(*layers.Ethernet)
		src_mac := string(ethPacket.SrcMAC)
		dst_mac := string(ethPacket.DstMAC)
   
		from_coms, from_exists := m.history[src_mac]
		if !from_exists {	
			from_coms = make(map[string]int64)
			m.history[src_mac] = from_coms
		}
		_, to_exists := from_coms[dst_mac]
		if ! to_exists {
			m.history[src_mac][dst_mac]=0
		} else {
			m.history[src_mac][dst_mac]++
		}
	}
	counter.Update(p)
}


func (m*L2ComMetricCounter)Differs( m2 *NetworkProfileMetric ) (string, bool){
	// TODO
	return "",false	
}

func (m*L2ComMetricCounter)Dump() string {
	var dump string
	dump += "L2ComMetricCounter:"
	for src, idx := range( m.history ) {
		dump += "<" + src +" =>" + ""
	}
	return dump
}


// Network trafic profile
type NetworkProfile struct {
	Metrics []NetworkProfileMetric
}

func (p *NetworkProfile)registerMetric( m NetworkProfileMetric ){
	p.Metrics = append(p.Metrics,m)
}

func main() {
    // Check if file argument is provided
    if len(os.Args) < 2 {
        fmt.Println("Please provide a pcap file to read")
        os.Exit(1)
    }

    // Open up the pcap file for reading
    handle, err := pcap.OpenOffline(os.Args[1])
    if err != nil {
        log.Fatal(err)
    }
    defer handle.Close()

	var profile     NetworkProfile
	var MACsMetric   

    // Loop through packets in file
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {

		var src_mac, dst_mac net.HardwareAddr
		var src_ip,  dst_ip net.IP

        // Extract and print the Ethernet layer
        ethLayer := packet.Layer(layers.LayerTypeEthernet)
        if ethLayer != nil {
            ethPacket, _ := ethLayer.(*layers.Ethernet)
            src_mac = ethPacket.SrcMAC
            dst_mac = ethPacket.DstMAC
        }

        // Extract and print the IP layer
        ipLayer := packet.Layer(layers.LayerTypeIPv4)
        if ipLayer != nil {
            ipPacket, _ := ipLayer.(*layers.IPv4)
            src_ip = ipPacket.SrcIP
            dst_ip = ipPacket.DstIP			
        }

		fmt.Printf("Src<%s>[%s] -> Dst<%s>[%s]\n", src_ip, src_mac, dst_ip, dst_mac )
        // Print the packet details
        //fmt.Println(packet.String())

		for _, metric := range profile.Metrics {
			metric.Update(&packet)
		}

    }

	// Show stats
	for _, metric := range profile.Metrics {
			fmt.Println( metric.Dump() )
	}

}
