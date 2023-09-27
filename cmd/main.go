
package main

import (
	"os"
    "fmt"                   // Import the fmt package to print messages to the console.
    "log"                   // Import the log package to log errors to the console.
    "github.com/google/gopacket/pcap" // Import the pcap package to capture packets.
    "github.com/google/gopacket" // Import the gopacket package to decode packets.
    "github.com/google/gopacket/layers" // Import the layers package to access the various network layers.
	"net"
)

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


    }
}
