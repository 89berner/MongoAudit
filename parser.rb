#!/usr/bin/ruby

require 'pty'
require 'pp'

def run_program(cmd)
	$stdout.sync = true
	#begin
	templine = ""
	  PTY.spawn( cmd ) do |stdin, stdout, pid|
	    puts "In pty for #{cmd}!"
	#    begin
		      stdin.each do |line|
		      		#puts "VIENDO a #{line}"
		      		if line.start_with?("PPPPPPPPPPPPPPPP")
		      			puts line.gsub("PPPPPPPPPPPPPPPP","")
		      			next
		      		end
		      		templine = templine + line.gsub(/[^a-zA-Z_0-9\-\{\} ,\@:\.,\"]/,"")
		      		if line.strip().end_with?("AAAAAAA")
		      			templine = templine.gsub("AAAAAAA","")
		      			if (line.include?(",") and line.split(",").length > 3)
		      				processline(templine)
		      			end
		      			@count = @count + 1
			         	if @count % 1000 == 0
				       	   puts "Eventos por segundo: #{@count / (Time.now.to_i - @start) }"
				        end
		      			templine = ""
		      		end
		       end
	#    rescue 
	#      puts "Error inside ptyt"
	#      end
	  end
	#rescue 
	#  puts "The child process exited!"
	#end	
end

def processline(line)

  #begin
	
	  #check if its auth
	  message = ""
	  #puts "RAW: #{line}"
	
	  sline = line.split(",")
	
	  dstport = sline[1].split(":")[1]
	  dstip = sline[1].split(":")[0]
	  srcport = sline[0].split(":")[1]
	  srcip = sline[0].split(":")[0]
	
	  server = ""
	  
	  if dstport == "6612"
	  	server = dstip
	  else
	  	server = srcip
	  end  
	  
	  cluster_name = "workshop"
	
	
	  timenow = Time.now.strftime("%b %d %H:%M:%S")
	
	  if line.include?("user:") and line.include?("nonce:") and line.include?("key:") and line.include?("authenticate")  #and line.include?("user") and line.include?("nonce") and line.include?("key")
	  	#Proceso a 10.32.165.113:1169,10.32.164.94:6612,testmon.$cmd,,,query,{ authenticate: 1.0, user: "testmon_WPROD", nonce: "318b2ad5bd56c512", key: "d3ff55b886621fbae183d9ca4e7d2f73" }  ntoreturn: -1 ntoskip: 0
	
	  	puts "#{srcip} + #{dstip} AUTH"
	  	schema = line.split(",")[2].split(".")[0]
	  	user = line.split('user: "')[1].split('"')[0]
	
	  	message = "#{timenow},#{cluster_name},#{server},#{user},#{schema},#{line}"
	  	#subo a hash
	  	@conexiones[srcip + ":" + srcport + ":" + dstip + ":" + dstport] = user + ":" + schema
	  	@conexiones[dstip + ":" + dstport + ":" + srcip + ":" + srcport] = user + ":" + schema
	  else
	     	#puts "Busco a esta conexion"
	     	user_schema = @conexiones[srcip + ":" + srcport + ":" + dstip +  ":" + dstport]
	     	if user_schema != nil and user_schema.include?(":")
	     		user = user_schema.split(":")[0]
	     		schema = user_schema.split(":")[1]
	  		message = "#{timenow},#{cluster_name},#{server},#{user},#{schema},#{line}"
	  	else
	  		user = ""
	  		schema = ""
	  		userline = line.split(",")[2]
	  		if userline.include?(".")
	  			user = userline.split(".")[0]
	  			schema = userline.split(".")[1]
	  		end
	  		message = "#{timenow},#{cluster_name},#{server},#{user},#{schema},#{line}"
	  	end
	  end
	
	  puts message
	  #$stdin.gets.chomp()
	  @lastlog = Time.now
	  @file.puts(message)
	  
    #rescue
    #	puts line
    #end

end

@conexiones = Hash.new

@file = File.open("/var/log/mongoqueries.log", 'a')
@file.sync = true
@start = Time.now.to_i
@count = 0
@lastlog = Time.now
@cluster = Hash.new

$stdout.sync = true

sleep 1

cmd = "./mongosniff 6612" 
last = nil
run_program(cmd)
#last = Thread.new { run_program(cmd) }
#while(1)
#	if (@lastlog < (Time.now-60))
#		puts "last log es: #{@lastlog} y hace 15 segs es #{Time.now-10}"
#		@lastlog = Time.now
#		Thread.kill(last)
#		%x[pkill mongosniff]
#		last = Thread.new { run_program(cmd) }
#	else
#		puts "Lastlog es de #{@lastlog}"
#	end
#	sleep 30

#end
