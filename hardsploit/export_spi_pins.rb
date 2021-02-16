#!/usr/bin/ruby
#===================================================
#  Coded by Konstantinos Xynos (2020)
#  Version: 1.0
#  Based on Hardsploit API - By Opale Security
#  www.opale-security.com || www.hardsploit.io
#  License: GNU General Public License v3
#  License URI: http://www.gnu.org/licenses/gpl.txt
#===================================================

#
# SPI I/O Pins on Hardsploit
# Assuming they are on default layout
#
# Pin A0 : Clock (CLK)
# Pin A1 : Cable Select (CS)
# Pin A2 : MOSI (SI)
# Pin A3 : MISO (SO)
#
require 'optparse'
require 'io/console'
require 'logger'
require_relative '../HardsploitAPI/Core/HardsploitAPI'
require_relative '../HardsploitAPI/Modules/SPI/HardsploitAPI_SPI'

$logFilePath = File.expand_path(File.dirname(__FILE__)) + "/hs_error.log"
$filepath = File.expand_path(File.dirname(__FILE__)) + "/hs_spi_export.bin"

$endTime_ = ''
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
      'spi_speed' => '5.00',
      'spi_command' => 3
    }

def select_export_file
    unless $filepath.nil?
      $file = File.open("#{$filepath}", 'w')
    end
    rescue Exception => msg
      logger = Logger.new($logFilePath)
      logger.error msg
end

def close_file
    unless $file.nil?
      $file.close
    end
    rescue Exception => msg
      logger = Logger.new($logFilePath)
      logger.error msg
end

def callbackInfo(receiveData)
	#print receiveData  + "\n"
end

def callbackData(receiveData)
	if receiveData != nil then
		#puts "received #{receiveData.size}"
	  	#p receiveData
		$file.write(receiveData.pack("C*"))
	else
		puts "[!] ISSUE BECAUSE DATA IS NIL"
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

puts " ** Hardsploit SPI export ** "

begin
  @options = {}
  @options[:load_firmware] = true
  OptionParser.new do |opts|
    opts.banner =  "usage: #{$0} [options]"

    opts.on("-p [PINS]", "--pins [PINS]",["0p3","4p7","3p0","7p4","default"], "Pick which pins to use. [0p3, 4p7, 3p0, 7p4, default]") do |pins_|
      @options[:pins] = pins_
      puts pins_.nil?
      if pins_.nil? then
        puts "[-] PINS needs a correct argument."
        exit(false)
      end
    end
    opts.on("-n", "--nofirmware", "Don't automatically load the FPGA firmware (load at least once after powering on or changing functionality)") do
      @options[:load_firmware] = false
      puts "[!] No FPGA firmware will be loaded (not always needed, but if you get errors try loading.)"
    end
    opts.on_tail("-h", "--help", "Show this message") do
      puts opts
      exit
    end
  end.parse!
rescue OptionParser::InvalidOption
  puts "Incorrect option ptovided"
  exit(false)
end

HardsploitAPI.callbackInfo = method(:callbackInfo)
HardsploitAPI.callbackData = method(:callbackData)
HardsploitAPI.callbackSpeedOfTransfert = method(:callbackSpeedOfTransfert)
HardsploitAPI.callbackProgress = method(:callbackProgress)
HardsploitAPI.id = 0  # id of hardsploit 0 for the first one, 1 for the second etc

begin
  HardsploitAPI.instance

rescue HardsploitAPI::ERROR::HARDSPLOIT_NOT_FOUND
  puts "[-] HARDSPLOIT Not Found"
  exit(false)
rescue HardsploitAPI::ERROR::USB_ERROR
  # HardsploitAPI.reset_device_access
  puts "[-] USB ERRROR              "
  exit(false)
end

if @options[:load_firmware] then
  puts "[!] Loading SPI firmware loaded to FPGA"
  HardsploitAPI.instance.loadFirmware("SPI")
  $percent_prv=0
  puts "\n" # add a bracket and a new line 
end

puts "[+] Number of hardsploit detected :#{HardsploitAPI.getNumberOfBoardAvailable}"
HardsploitAPI.instance.getAllVersions

crossvalue = Array.new
#Default wiring
# Actuall mapping 0-CLK, 1-CS, 2-SI, 3-SO

for i in 0..63
  crossvalue.push i
end

puts "[!] Warning : Some configurations won't work since line interference casues issues. Keep that in mind."
case @options[:pins]
when "0p3"
  puts "[!] Custom pins based on Saleae logic cable (0 to 3)"
  puts "    Key: Function: Hardsploit pin - Saleae Pro Pin"
  puts "\tCS: A0 - pin 0 | SO: A1 - pin 1"
  puts "\tSI: A2 - pin 2 | CLK: A3 - pin 3" 
  crossvalue[0] = 1
  crossvalue[1] = 3
  crossvalue[2] = 2
  crossvalue[3] = 0
  HardsploitAPI.instance.setWiringLeds(value:0x000000000000000F) # highlight the ones we picked
when "4p7"
  puts "[!] Custom pins based on Saleae logic cable (4 to 7)"
  puts "\tKey: Function: Hardsploit pin - Saleae Pro Pin"
  puts "\tCS: A4 - pin 4 | SO: A5 - pin 5"
  puts "\tSI: A6 - pin 6 | CLK: A7 - pin 7" 
  crossvalue[0] = 4
  crossvalue[1] = 5
  crossvalue[2] = 6
  crossvalue[3] = 7

  crossvalue[4] = 1
  crossvalue[5] = 3
  crossvalue[6] = 2
  crossvalue[7] = 0
  HardsploitAPI.instance.setWiringLeds(value:0x00000000000000F0) # highlight the ones we picked
when "3p0"
  puts "[!] Custom pins based on Saleae logic cable (3 to 0)"
  puts "    Key: Function: Hardsploit pin - Saleae Pro Pin"
  puts "\tCS: A3 - pin 0 | SO: A2 - pin 1"
  puts "\tSI: A1 - pin 2 | CLK: A0 - pin 3"
  crossvalue[0] = 0
  crossvalue[1] = 2
  crossvalue[2] = 3
  crossvalue[3] = 1
  HardsploitAPI.instance.setWiringLeds(value:0x000000000000000F) # highlight the ones we picked
when "7p4"
  puts "[!] Custom pins based on Saleae logic cable (7 to 4)"
  puts "\tKey: Function: Hardsploit pin - Saleae Pro Pin"
  puts "\tCS: A7 - pin 4 | SO: A6 - pin 5"
  puts "\tSI: A5 - pin 6 | CLK: A4 - pin 7" 
  crossvalue[0] = 4
  crossvalue[1] = 5
  crossvalue[2] = 6
  crossvalue[3] = 7

  crossvalue[4] = 0
  crossvalue[5] = 2
  crossvalue[6] = 3
  crossvalue[7] = 1
  HardsploitAPI.instance.setWiringLeds(value:0x00000000000000F0) # highlight the ones we picked
when "default"
  puts "[!] Default pin layout CLK: A0, CS: A1, MOSI: A2, MISO: A3"
end


begin
  HardsploitAPI.callbackProgress = method(:callbackProgress)
  select_export_file

  HardsploitAPI.instance.setCrossWiring(value:crossvalue)
  puts "[+] HARDSPLOIT SPI any rewiring complete "

  @spi = HardsploitAPI_SPI.new(speed:@speeds[@chip_settings_['spi_speed']],mode:@chip_settings_['spi_mode'])
  
  puts "[+] HARDSPLOIT SPI export started "
  @spi.spi_Generic_Dump(readSpiCommand:@chip_settings_['spi_command'], startAddress:@chip_settings_['start_address'],
  stopAddress:@chip_settings_['spi_total_size']-1,sizeMax:@chip_settings_['spi_total_size'])

  close_file

  puts "\n[+] HARDSPLOIT SPI export completed successfully"
  puts "[+] " + $endTime_ 
  puts "[+] File saved in : " + $filepath 

rescue HardsploitAPI::ERROR::HARDSPLOIT_NOT_FOUND
  puts "[-] HARDSPLOIT Not Found\n"
  close_file
  exit(-1)
rescue HardsploitAPI::ERROR::USB_ERROR
  # HardsploitAPI.reset_device_access
  puts "[-] USB ERRROR              "
  close_file
  exit(-1)
rescue SystemExit, Interrupt
  puts "[!] Ended by user           "
  close_file
  # HardsploitAPI.reset_device_access
  exit(-42)
end

