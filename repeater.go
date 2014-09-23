package main

import (
	"time"
	"os"
	"net"
	"fmt"
	//"github.com/akrennmair/gopcap"
	"log"
	"pcap"
	//"math/rand"
	"strings"
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
var localip string

var f *os.File

func UnixNow() int64 {
	return time.Now().Unix()
}

func main() {
	fmt.Print("Comienza Repeater\n")	 
	fmt.Printf("Poner como parametro el puerto a repetir\n")

	srcport := os.Args[1] // port


	fmt.Printf("Inicializo escuchando en el puerto %s y repito al puerto %s\n",srcport)


	msgchan := make(chan []byte)

	ln, err := net.Listen("tcp", fmt.Sprintf(":%s",srcport))
	if err != nil {
		// handle error
	}
	defer ln.Close()

	fmt.Println("Abro el archivo")
	f, err = os.OpenFile("/var/log/mysqlqueries.txt", os.O_CREATE|os.O_WRONLY, 0666)
	 if err != nil {
              panic(err)	
	 }	
	 
	go printMessages(msgchan)

	for {
		conn, err := ln.Accept()
		if err != nil {
			// handle error
			continue
		}
		log.Printf("Nueva conexion de %v.", conn.RemoteAddr())
		go handleConnection(conn,msgchan,f)

	          tex := fmt.Sprintf("%s",conn.LocalAddr())
	          tex = strings.Split(tex, ":")[0]
	          localip = tex
	}

}

func handleConnection(c net.Conn, msgchan chan<- []byte,f *os.File) {
    buf := make([]byte, 4096)
    for {
        n, err := c.Read(buf)
        if err != nil || n == 0 {
            c.Close()
            log.Printf("Connection from %v closed.", c.RemoteAddr())
            break
        }
        msgchan <- buf[0:n]
    }
}

func printMessages(msgchan <-chan []byte ) {
	var eth = "eth0"
	log.Printf("Initializing Replay...")

	if handle, err := pcap.OpenLive(eth, 1600, false, 0); err != nil {
	  panic(err)
	} else if err := handle.SetBPFFilter("tcp and port 80"); err != nil {  // optional
	  panic(err)
	} else {
	       for msg := range msgchan {
	        tipo := fmt.Sprintf("%d", msg[0])

	        if tipo == "2"{
	        	handle.WritePacketData(msg[1:])
	        	//handleMysqlPacket(msg[1:])
	        }

	    } 
	}
}

func handleMysqlPacket(data []byte) { //, f *os.File
	log.Printf("En MongoParser con length %q", data)
}
