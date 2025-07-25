OSI (Open Systems Interconnection)

The seven layers are:

Layer 7: Application (HTTP, FTP - what your programs speak)
Layer 6: Presentation (Encryption, compression)
Layer 5: Session (Maintaining connections)
Layer 4: Transport (TCP, UDP - ensuring reliable delivery)
Layer 3: Network (IP - routing between networks)
Layer 2: Data Link (Ethernet - local network delivery)
Layer 1: Physical (Actual electrical signals)


The Network Layer Family (OSI Layer 3) : 

	FWPM_LAYER_INBOUND_IPPACKET_V4 / FWPM_LAYER_OUTBOUND_IPPACKET_V4
	packets at their most raw form.
	Example:
		Raw IP Header: Version=4, Length=1500, Protocol=6(TCP), Fragmented=Yes
		Source IP: 192.168.1.100
		Destination IP: 93.184.216.34
		Fragment: Part 1 of 3

The Transport Layer Family (OSI Layer 4) :

	FWPM_LAYER_INBOUND_TRANSPORT_V4 / FWPM_LAYER_OUTBOUND_TRANSPORT_V4
	This is where Windows has assembled those IP fragments and you can now see complete TCP or UDP headers.
	At this layer, you can detect connection attempts (SYN), connection teardowns (FIN), and resets (RST).
	It's like watching people shake hands to start a conversation or wave goodbye to end one
	Example:
		TCP Header: SourcePort=54231, DestPort=443
		Flags: SYN (Starting new connection)
		Sequence Number: 1234567
		Window Size: 65535

The layer between OSI Layer 4 and Layer 5 : 

	FWPM_LAYER_DATAGRAM_DATA_V4 
	This is a special Windows layer that sits between OSI Layer 4 and Layer 5.
	Microsoft created this because it's incredibly useful - you get complete,
	reassembled packets with their data, but before any application processing.
	Example:
		Complete packet: 192.168.1.100:54231 -> 93.184.216.34:443
		Protocol: TCP
		Data: 517 bytes of TLS encrypted data


The Session/Application Layer Family (OSI Layers 5-7)

	FWPM_LAYER_STREAM_V4
	This layer is fascinating because it represents OSI Layer 5 (Session) functionality.
	Windows gives you the actual TCP stream data here - 
	not individual packets, but the continuous stream of data as the application sees it.
	Imagine reading a book where someone else handles turning the pages for you
	- you just see the continuous story.
	Example:
		TCP Stream Data:
		"GET /index.html HTTP/1.1\r\n"
		"Host: example.com\r\n"
		"User-Agent: Mozilla/5.0...\r\n"

	
	FWPM_LAYER_ALE_* (Application Layer Enforcement)
	The ALE layers are Microsoft's clever solution to a problem the OSI model doesn't address well:
	"Which program on the computer is making this connection?"
	These layers straddle OSI Layers 4-7, 
	providing application identity information that the OSI model never contemplated.
	Key componenets:

		FWPM_LAYER_ALE_AUTH_CONNECT_V4: When an application tries to make an outbound connection
			Application: C:\Program Files\Google\Chrome\chrome.exe
			Process ID: 5678
			User: DESKTOP\John
			Attempting connection to: 142.250.80.78:443

		FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4: When an application wants to accept incoming connections
			Application: C:\Windows\System32\svchost.exe
			Service: Windows Update
			Accepting connection from: 13.107.4.52:443

		FWPM_LAYER_ALE_AUTH_LISTEN_V4: When an application starts listening on a port
			Application: C:\Program Files\Apache\httpd.exe
			Starting to listen on: 0.0.0.0:80
	
	
Special Purpose Layers:
	FWPM_LAYER_INBOUND_MAC_FRAME_* - 
		These operate at OSI Layer 2 (Data Link), 
		letting you see Ethernet frame information. 
		This is like looking at the addressing on the outside of an envelope before even checking what's inside
		Example:
				Source MAC: 00-14-22-01-23-45
				Destination MAC: 00-14-22-67-89-AB
				Type: IPv4 (0x0800)

	FWPM_LAYER_IPSEC_* - 
		These layers handle IPSec encryption, operating between OSI Layers 3 and 4.
		They let you inspect encrypted VPN traffic policies.


Some examples for legit traffic:

 * When a web browser connects to a website, you'll see:
 * 1. [ALE_CONNECT] chrome.exe attempting TCP connection to 1.2.3.4:443
 * 2. [DATAGRAM_DATA] Multiple packets flowing back and forth

 * 1. [ALE_LISTEN] httpd.exe starting to listen on 0.0.0.0:80
 * 2. [ALE_RECV_ACCEPT] httpd.exe receiving connection from client
 * 3. [DATAGRAM_DATA] Data exchange

