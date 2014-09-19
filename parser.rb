#!/usr/bin/ruby

require 'pty'
require 'pp'

def run_program(cmd)
	
	begin
	  PTY.spawn( cmd ) do |stdin, stdout, pid|
	    puts "In pty!"
	    begin
	      # Do stuff with the output here. Just printing to show it works
	      goon = false
	      fullstring = ""
	      stdin.each do |line|
	      	
	      	#puts "Reading line #{@count}"
	        if (line.include?("-->>") or line.include?("<<--") ) and line.include?("bytes")
	          goon = true
	          fullstring = fullstring.strip().gsub("\n","").gsub("\r","")
	          #puts "Proceso a #{fullstring}"
	          if !fullstring.include?("found device: eth0sniffing")
	          		processline(fullstring)
	          		@count = @count + 1
	          		if @count %10 == 0
	          			puts "Eventos por segundo: #{@count / (Time.now.to_i - @start) }"
	          		end
	          		#puts ""
	          end
	          fullstring = line
	        else
	          fullstring = fullstring + line
	        end
	      end
	    rescue Errno::EIO
	      puts "Errno:EIO error, but this probably just means " +
	            "that the process has finished giving output"
	    end
	  end
	rescue PTY::ChildExited
	  puts "The child process exited!"
	end	
	
	
end

def processline(line)

  #check if its auth
  message = ""
  #puts "RAW: #{line}"
  
  

  srcip = srcport = dstip = dstport = ""

  if line.split(" ")[1].include?("<<--")
	srcip = line.split(":")[0].gsub(" ","")
  	line = line.split(":")[1..-1].join(":")
  	srcport = line.split("  <<-- ")[0].gsub(" ","")
  	line = line.split("  <<-- ")[1..-1].join("  <<-- ")
  	dstip = line.split(":")[0].gsub(" ","")
  	line = line.split(":")[1..-1].join(":")
	dstport = line.split(" ")[0].gsub(" ","")
   else
	srcip = line.split(":")[0].gsub(" ","")
  	line = line.split(":")[1..-1].join(":")
  	srcport = line.split("  -->> ")[0].gsub(" ","")
  	line = line.split("  -->> ")[1..-1].join("  -->> ")
  	dstip = line.split(":")[0].gsub(" ","")
  	line = line.split(":")[1..-1].join(":")
	dstport = line.split(" ")[0].gsub(" ","")
    end

  line = line.split(" ")[1..-1].join(" ")
  
  server = ""
  if dstport == "6612"
  	server = dstip
  else
  	server = srcip
  end
  
  #puts "Server es #{server}"
  


  timenow = Time.now.strftime("%b %d %H:%M:%S")

  if line.include?("query: { authenticate:") #and line.include?("user") and line.include?("nonce") and line.include?("key")
  	schema = line.split(".")[0]
  	line = line.split(".")[1..-1].join(".")
  	user = line.split('user: "')[1].split('"')[0]

  	message = "#{timenow},#{server},#{srcip},#{srcport},#{dstip},#{dstport},#{schema},#{user},},#{line}"
  	#subo a hash
  	@conexiones[srcip + ":" + srcport + ":" + dstip] = user + ":" + schema
  else
     	#puts "Busco a esta conexion"
     	
     	user_schema = @conexiones[srcip + ":" + srcport + ":" + dstip]
     	if user_schema != nil and user_schema.include?(":")
     		user = user_schema.split(":")[0]
     		schema = user_schema.split(":")[1]
  		message = "#{timenow},#{server},#{srcip},#{srcport},#{dstip},#{dstport},#{schema},#{user},#{line}"
  	else
  		message = "#{timenow},#{server},#{srcip},#{srcport},#{dstip},#{dstport},,,#{line}"
  	end
  end

  puts message
  @lastlog = Time.now
  @file.write(message + "\n")

end

@conexiones = Hash.new

@file = File.open("/var/log/mongoqueries.log", 'a')
@file.sync = true
@start = Time.now.to_i
@count = 0
@lastlog = Time.now

cmd = "./mongosniff 6612" 
last = nil
last = Thread.new { run_program(cmd) }
while(1)
	if (@lastlog < (Time.now-10))
		puts "last log es: #{@lastlog} y hace 15 segs es #{Time.now-10}"
		@lastlog = Time.now
		Thread.kill(last)
		last = Thread.new { run_program(cmd) }
	else
		#puts "Lastlog es de #{@lastlog}"
	end

end
