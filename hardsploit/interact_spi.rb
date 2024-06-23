#!/usr/bin/ruby
#===================================================
#  Coded by Konstantinos Xynos (2024)
#  Version: 1.0
#  Based on Hardsploit API - By Opale Security
#  www.opale-security.com || www.hardsploit.io
#  License: GNU General Public License v3
#  License URI: http://www.gnu.org/licenses/gpl.txt
#===================================================
require 'io/console'
require 'logger'
require_relative '../HardsploitAPI/Core/HardsploitAPI'
require_relative '../HardsploitAPI/Modules/SPI/HardsploitAPI_SPI'

$logFilePath = File.expand_path(File.dirname(__FILE__)) + "/hs_error.log"

$endTime_ = nil
$percent_prv = 0

@speeds = {
      '25.00' => 3,
      '18.75' => 4,
      '15.00' => 5,
      '12.50' => 6,
      '10.71' => 7,
      '9.38' => 8,
      '7.50' => 10,
      '5.00' => 15,
      '3.95' => 19,
      '3.00' => 25,
      '2.03' => 37,
      '1.00' => 75,
      '0.50' => 150,
      '0.29' => 255
    }

@chip_settings_ = {
      'spi_total_size' => 4194304,
    # 'spi_total_size' => 8388608,
      'start_address' => 0,
      'spi_mode' => 0,
      'spi_speed' => '15.00',
      'spi_command' => 3
    }

require 'optparse'


options = {}
items= {}
OptionParser.new do |opt|
  opt.on('-n', '--nofirmware', 'Avoid uploading firmware') do
    options[:nofirmware] = true
  end

  opt.on('-c', '--command hex_value1,hex_value2,...', Array, 'An input array used for command input, use hex values e.g., 9f,0,0,0,0') do |items|
    options[:cmd_array] = items
  end
  opt.on('-o', '--nooutput', 'Avoid output status messages, only the output result is printed') do
    options[:nooutput] = true
  end
end.parse!




def callbackInfo(receiveData)
	#print receiveData  + "\n"
end

def callbackData(receiveData)
	if receiveData != nil then
		#puts "received #{receiveData.size}"
	  	#p receiveData
		$file.write(receiveData.pack("c*"))
	else
		puts "[-] ISSUE BECAUSE DATA IS NIL"
	end
end

def callbackSpeedOfTransfert(receiveData)
	#puts "Speed : #{receiveData}"
end

def callbackProgress(percent:,startTime:,endTime:)
	if percent > $percent_prv
		$percent_prv = percent
		print "[+] Progress : #{percent}%  Start@ #{startTime}  Stop@ #{endTime} " + "\r" 
		$stdout.flush
	end
	$endTime_ = "Elasped time #{(endTime-startTime).round(4)} sec"
#	puts "Elasped time #{(endTime-startTime).round(4)} sec"
end

if options[:nooutput] then
  $stdout = File.new( '/dev/null', 'w' )
else
  $stdout = STDOUT
end

puts " ** Hardsploit SPI command ** " 
puts "[+] Avoid uploading firmware flag set: #{options[:nofirmware]}" if options[:nofirmware] 
#puts "Input array: [#{options[:cmd_array].join(',')}]" if options[:cmd_array]

HardsploitAPI.callbackInfo = method(:callbackInfo)
HardsploitAPI.callbackData = method(:callbackData)
HardsploitAPI.callbackSpeedOfTransfert = method(:callbackSpeedOfTransfert)
HardsploitAPI.callbackProgress = method(:callbackProgress)
HardsploitAPI.id = 0  # id of hardsploit 0 for the first one, 1 for the second etc

begin
puts "[+] Number of hardsploit detected :#{HardsploitAPI.getNumberOfBoardAvailable}"  
HardsploitAPI.instance.getAllVersions 

rescue HardsploitAPI::ERROR::HARDSPLOIT_NOT_FOUND
   puts "[-] HARDSPLOIT Not Found"
   exit(false)
rescue HardsploitAPI::ERROR::USB_ERROR
   puts "[-] USB ERRROR              "
   exit(false)
end

#if ARGV[0] != "nofirmware" then
if not options[:nofirmware] then
   puts "[+] Loading SPI firmware onto HARDSPLOIT"  
   HardsploitAPI.instance.loadFirmware("SPI")
   $percent_prv=0
   puts "\n" # add a bracket and a new line 
end


begin

HardsploitAPI.callbackProgress = method(:callbackProgress)
#select_export_file

@spi = HardsploitAPI_SPI.new(speed:@speeds[@chip_settings_['spi_speed']],mode:@chip_settings_['spi_mode'])

puts "[+] HARDSPLOIT SPI command started "  

opt_array = options[:cmd_array]
puts "[+] Sending command: " + opt_array.to_s 
opt_array = opt_array.map { |hex| hex.to_i(16) }
cmd_array1 = "[#{opt_array.join(',')}]"
puts "[+] Sending command(int): " + cmd_array1 
cmd_array1 = cmd_array1.split(/\D+/).reject(&:empty?).map(&:to_i)

r_data = @spi.spi_Interact(payload:cmd_array1)

rr_data= r_data.map { |hex| hex.to_s(16) }
if options[:nooutput] then
  $stdout = STDOUT
  puts "[#{rr_data.join(',')}]"
  $stdout = File.new( '/dev/null', 'w' )
else
  puts "[+] Reply: [#{rr_data.join(',')}]"
end

puts "\n[+] HARDSPLOIT SPI command completed successfully" 
if $endTime_ != nil then
  puts "[+] " + $endTime_ 
end

rescue HardsploitAPI::ERROR::HARDSPLOIT_NOT_FOUND
   puts "[-] HARDSPLOIT Not Found\n"
   exit(false)
rescue HardsploitAPI::ERROR::USB_ERROR
   puts "[-] USB ERRROR              "
   exit(false)

end
