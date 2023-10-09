package abnormalix

import (

	// Import the fmt package to print messages to the console.
	// Import the log package to log errors to the console.
	// Import the pcap package to capture packets.
	"encoding/binary"

	"github.com/google/gopacket"        // Import the gopacket package to decode packets.
	"github.com/google/gopacket/layers" // Import the layers package to access the various network layers.
)

type NetworkProfileMetric interface {
	//	Differs(m *NetworkProfileMetric) (string, bool)
	Update(p *gopacket.Packet)
	Dump() string
}

type PacketCounter struct {
	PacketsCount int
	SizeTotal    int
}

func (c *PacketCounter) Update(p gopacket.Packet) {
	c.PacketsCount++
	data := p.Data()
	c.SizeTotal += binary.Size(data)
}

// Level 2 communication profile
type L2ComMetricCounter struct {
	history map[string]map[string]int64
	counter PacketCounter
}

func (m *L2ComMetricCounter) Update(p gopacket.Packet) {
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
		if !to_exists {
			m.history[src_mac][dst_mac] = 0
		} else {
			m.history[src_mac][dst_mac]++
		}
	}
	m.counter.Update(p)
}

/*
func (m *L2ComMetricCounter) Differs(m2 *NetworkProfileMetric) (string, bool) {
	// TODO
	return "", false
}
*/

func (m *L2ComMetricCounter) Dump() string {
	var dump string
	dump += "L2ComMetricCounter:"
	for src := range m.history {
		dump += "<" + src + " =>" + ""
	}
	return dump
}

// Network trafic profile
type NetworkProfile struct {
	Metrics []NetworkProfileMetric
}

func (p *NetworkProfile) RegisterMetric(m *NetworkProfileMetric) {
	(*p).Metrics = append((*p).Metrics, m)
}
