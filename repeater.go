	package main
	
	import (
		"time"
		"os"
		"net"
		"fmt"
		//"github.com/akrennmair/gopcap"
		"log"
		"io"
		"pcap"
		//"math/rand"
		"strings"
		//"regexp"
	//	"encoding/binary"
	//	"bytes"
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
	
		fmt.Printf("Inicializo escuchando en el puerto %s\n",srcport)
	
		ln, err := net.Listen("tcp", fmt.Sprintf(":%s",srcport))
		if err != nil {
			// handle error
		}
		defer ln.Close()
	
		for {
			conn, err := ln.Accept()
			if err != nil {
				// handle error
				continue
			}
			log.Printf("Nueva conexion de %v.", conn.RemoteAddr())
			go handleConnection(conn,f)
	
		          tex := fmt.Sprintf("%s",conn.LocalAddr())
		          tex = strings.Split(tex, ":")[0]
		          localip = tex
		}
	}
	
	func handleConnection(c net.Conn, f *os.File) {
	
		defer func() {
	             if r := recover(); r != nil {
	                  fmt.Println("Recovered in handleConnection", r)
	             }
		}()
	
	    msgchan := make(chan []byte,1024*1024*50)
	    go printMessages(msgchan)
	
	    var contador = 0;
	    var nzero = 0;
	
	    var size uint32
	    var rest uint32
	
	    for {
	    		buf2 := make([]byte, 2)
	    		
		        for {
			        xn, xerr := io.ReadFull(c, buf2)
			        
			        if xerr != nil || xn == 0 {
			            time.Sleep(1)
			            log.Printf("Espero 1 seg para buf2..")
			            xxn, xxerr := io.ReadFull(c, buf2)
			            if xxerr != nil || xxn == 0 {
				            log.Printf("Connection from %v closed with xxn: %d.", c.RemoteAddr(), xxn)
				            continue
				    }
			        }

			        if (xn != 2) {
			        	fmt.Printf("En primera lectura lei %d\n",xn)
			        }
			        
			        rsize := buf2[0]
			        size = uint32(rsize)
			        rrest := buf2[1]
			        rest = uint32(rrest)
			        
			        if (size != 0) {
			        	break
			        }
				
			        log.Printf("Me dio size: %d y rest %d ",size,rest)
		        
		        	
		        }

	        
	        xtam := size*100-rest
	        
		buf := make([]byte, size*100)
		var n int
	        for {
	        n, err := io.ReadFull(c, buf)
		        if err != nil || n == 0 {
		        	log.Printf("Waiting with nzero: %d to read %d ",nzero,size*100)
		        	nzero = nzero + 1
		        	time.Sleep(1000 * time.Millisecond)
		        	continue
		        }
	        	break
	        }

	        tam := n
	
	        contador = contador + 1
	        if (contador % 100 == 0 ) {
	        	fmt.Printf("handleConnection: Me dice que el tamaño total es %d con un size de %d y un rest de %d y el mensaje es %v\n", xtam, size,rest, buf2)
	        	fmt.Printf("handleConnection: %d y lei %d bytes para mandar %d y xtam %d y mensaje %v\n", contador,n,tam, xtam,buf)
	        }
	        
	        msgchan <- buf[0:xtam]
	    }
	}
	
	func printMessages(msgchan <-chan []byte) {
	
		defer func() {
	             if r := recover(); r != nil {
	                  fmt.Println("Recovered in printMessages", r)
	             }
		}()
		
		var contador = 0;
	
		var eth = "eth0"
		//log.Printf("Initializing Replay...")
		
	
		if handle, err := pcap.OpenLive(eth, 10240, false, 0); err != nil {
		  panic(err)
		} else if err := handle.SetBPFFilter("tcp and port 80"); err != nil {  // optional
		  panic(err)
		} else {
		       fmt.Println("Esperando para mandar de: %d", contador)
		       for msg := range msgchan {
		        contador = contador + 1
		        
		        if (contador % 100 == 0) {
		        	fmt.Printf("printMessages: Cantidad: %d y tamaño %d\n", contador, len(msg))
		        }
	
		        handle.WritePacketData(msg)
		    } 
		}
	}
	
