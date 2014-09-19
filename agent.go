/*
 * agent.go
 *
 * requires the gopcap library to be installed from:
 *   https://github.com/akrennmair/gopcap
 *
 */

package main

import (
	"time"
	//"encoding/binary"
	"os"
	"net"
	"fmt"
	"github.com/akrennmair/gopcap"
	"log"
	"math/rand"
	//"strings"
	//"regexp"
)

var start int64 = UnixNow()
var packetcount int32 = 0
var verbose bool = false
var dirty bool = false
var format []interface{}
var port uint16
var connections map[string]string = make(map[string]string)
var dbusers map[string]string = make(map[string]string)


func UnixNow() int64 {
	return time.Now().Unix()
}

func main() {
	rand.Seed(time.Now().UnixNano())
	
	eth := os.Args[1] // interface
	port := os.Args[2] // port
	destination := os.Args[3] // destination
	destinationport := os.Args[4] // destination
	
	fmt.Printf("Opciones son: 1) Interfaz 2) Puerto (puede ser * ) 3) IP DESTINO 4) PUERTO DESTINO")

	fmt.Printf("Inicializo escuchando en la interfaz %s bajo el puerto %s y mando a %s:%s\n",eth,port,destination,destinationport)

	log.SetPrefix("")
	log.SetFlags(0)

	log.Printf("Initializing Agent sniffing on %s...",port)
	iface, err := pcap.Openlive(eth, 10240, false, 0)
	if iface == nil || err != nil {
		msg := "unknown error"
		if err != nil {
			msg = err.Error()
		}
		log.Fatalf("Failed to open device: %s", msg)
	}

	if port != "*" {
		err = iface.Setfilter(fmt.Sprintf("tcp port %s",port))
		if err != nil {
			log.Fatalf("Failed to set port filter: %s", err.Error())
		}
	}

	last := UnixNow()
	var pkt *pcap.Packet = nil
	var rv int32 = 0     

	var period int32 = 3

	log.Print("Ahora voy paquete por paquete")	 

	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%s",destination,destinationport))
	if err != nil {
		log.Fatalf("No me pude conectar a un parser: %s", err.Error())
	}

	for rv = 0; rv >= 0; {
		for pkt, rv = iface.NextEx(); pkt != nil; pkt, rv = iface.NextEx() {

			tipo := make([]byte, 1)
			tipo[0] = 2
			var pos byte = 14

			pos += pkt.Data[pos] & 0x0F * 4
			packetcount = packetcount + 1
			pos += byte(pkt.Data[pos+12]) >> 4 * 4

			//if len(pkt.Data[pos:]) <= 0 {
			//	continue
			//}
			
			send := append(tipo,pkt.Data...)

			if _, err := conn.Write([]byte(send)); err != nil {
				log.Fatalf("No me pude conectar a un parser: %s", err.Error())
			}

			if last < UnixNow()-int64(period) {
				message := fmt.Sprintf("Paquetes por segundo: %d\n", packetcount / period)
					
				log.Print(message)
				last = UnixNow()
				packetcount = 0
			}
		}
	}
}
