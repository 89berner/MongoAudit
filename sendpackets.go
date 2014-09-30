package main

import (
	"time"
	"os"
	"fmt"
	"log"
	"pcap"
	//"math/rand"
	//"regexp"
	"strconv"
)

 import ( pcap2 "github.com/akrennmair/gopcap" )

var start int64 = UnixNow()
var packetcount int32 = 0
var verbose bool = false
var dirty bool = false
var format []interface{}
var port uint16
var connections map[string]string = make(map[string]string)
var dbusers map[string]string = make(map[string]string)
var localip string

var f *os.File

func UnixNow() int64 {
	return time.Now().Unix()
}

//Este script va a escuchar a un puerto, obtener 1 paquete de ese puerto y repetirlo amount veces
//al mismo puerto asi lo escuchan
func main() {
	fmt.Print("Comienza SendPackets\n")	 
	fmt.Printf("Poner como parametro la cantidad de paquetes para repetir y el puerto\n")
	amount := os.Args[1] // port
	port := os.Args[2] // port
	
	camount, err := strconv.Atoi(amount)
	err = err

	fmt.Printf("Voy a escuchar un paquete del puerto %s y repetirlo %s veces\n",port, amount)

        iface, err := pcap2.Openlive("eth0", 10240, false, 0)
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
  	
	var pkt *pcap2.Packet = nil
	var rv int32 = 0     

	msgchan := make(chan []byte)
	go printMessages(msgchan)

	pkt, rv = iface.NextEx()
	for i := 0; i < camount; i++ {
		msgchan <- pkt.Data
		rv = rv
	}


}

func printMessages(msgchan <-chan []byte ) {

	defer func() {
             if r := recover(); r != nil {
                  fmt.Println("Recovered in printMessages", r)
             }
	}()
	
	var contador = 0

	var eth = "eth0"
	log.Printf("Initializing Replay...")

	if handle, err := pcap.OpenLive(eth, 10240, false, 0); err != nil {
	  panic(err)
	} else if err := handle.SetBPFFilter("tcp and port 80"); err != nil {  // optional
	  panic(err)
	} else {
	       for msg := range msgchan {
	        	handle.WritePacketData(msg)
	        	contador = contador + 1
	        	if (contador % 1000 == 0) {
	        		fmt.Println("Cantidad: %d", contador)
	        	}
	    } 
	}
}

