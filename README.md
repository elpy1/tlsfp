# tlsfp
Run a local HTTPS server or search through a pcap file and return client TLS data and/or fingerprints([**ja3**](https://github.com/salesforce/ja3) and [**ja4**](https://github.com/FoxIO-LLC/ja4)).

## Background
I first became interested in TLS fingerprinting when it was offered as a solution by a CDN provider at one of my previous jobs. The Solutions Engineer explained that we could use their new TLS fingerprint hash (instead of a combination of IP address and User-Agent) to block malicious clients who breach the WAF. Another engineer had analysed our WAF data from the previous month and identified a couple of fingerprints to block. I was told the malicious actor had been rotating their IP address to evade detection, enabling them to scrape our website in peace by staying under WAF rate limits. And now, using their SSL fingerprint, we could block them completely.

Wow. That's cool, I thought. I was fascinated but had lots of thoughts and questions running through my mind. *Is it really that easy to uniquely identify a user from a TLS handshake?* *That doesn't seem very privacy-preserving.* *Farewell to CGNAT issues?* *How unique are TLS fingerprints?* *What specific data is used to build the fingerprint?* *You're meant to be privacy-conscious elpy, how could you not know about this?* I responded that it sounded great but I wanted to look into it and better understand how it worked before rolling it out. I said I'd get back to them soon and set myself a weekly reminder in slack to investigate.

A couple of weeks had passed and I got a reminder email about the deployment. I was busy and hadn't yet looked into it. I confirmed the WAF change had been rolled out to staging and did some quick tests using curl and firefox to make sure nothing was broken. *OK*. *All looks good*. Let's deploy it. Well, 5 minutes later we had our first complaint that the website was down. Luckily it came internally from a staff member, so gathering information for troubleshooting was easy.

It turned out that all Chrome users (using the latest release at the time) were blocked. The WAF change was immediately rolled back.

**TLDR**: A WAF deployment that blocked clients based on a TLS fingerprint inadvertently blocked a large chunk of website visitors who were using a specific version of Chrome browser.

## Getting started
This project was a great learning experience. Some of the more interesting and challenging bits:
- Reading through RFCs to understand the structure of a TLS record and handshake
- Differences between TLS 1.2 and 1.3
- Working with binary data and unpacking TLS handshake data
- How to check the socket recv data before actually consuming the buffer (to capture the client handshake and decide whether to initiate the server-side handshake).
- Building a very crude barebones HTTP server

Each of these could easily be a separate blog post!

I can confidently say that TLS fingerprinting is not as powerful as you might think, and fingerprints can easily be spoofed. Malicious actors are most likely already abusing this and I assume it will become more difficult to rely on TLS fingerprints in future.

Special mention for these excellent resources:
- **Cloudflare**: [What happens in a TLS handshake?](https://www.cloudflare.com/learning/ssl/what-happens-in-a-tls-handshake/)
- **Michael Driscoll** (github: [syncsynchalt](https://github.com/syncsynchalt)): [The Illustrated TLS 1.3 Connection: Every byte explained and reproduced](https://tls13.xargs.org/#client-hello/annotated)
- **Command Line Fanatic**: [A walk-through of an SSL handshake](https://commandlinefanatic.com/cgi-bin/showarticle.cgi?article=art059)


## Requirements
- Python 3.10+
- Python [curio](https://github.com/dabeaz/curio) module for async socket operations. See [requirements.txt](requirements.txt).

## How it works
- [tlsfp.py](tlsfp.py) is imported and contains functions for unpacking TLS handshake data (specifically the ClientHello message) and building the fingerprints.
- [tls_vars.py](tls_vars.py) is imported and contains data for verifying and mapping numerous bits of data found in the TLS handshake e.g. cipher suites, signature algorithms etc.
- [http_helpers.py](http_helpers.py) is imported and contains helper functions for our **very** crude HTTPS server.
- [server.py](server.py) starts a TCP server and listens on your chosen port. When a connection is received, we check the data in the socket buffer for a TLS handshake message. If it appears valid the server-side TLS handshake is initiated, and the data in the socket recv buffer is consumed. We then check for a valid HTTP request and respond with the client's TLS data (as hex strings) and fingerprints in JSON format.
- [pcap.py](pcap.py) reads a given binary file, finds all TLS **ja4** fingerprints and prints them out.

## Installation and Usage
These scripts were created in an effort to learn more about TLS fingerprinting. I've only tested them on my local machine (using `OpenSSL 3.2.1 30 Jan 2024 (Library: OpenSSL 3.2.1 30 Jan 2024)` and `Python 3.12`) with TLS 1.2 and TLS 1.3 data. They are not production-ready.  
  
**I strongly recommend only using them locally for learning purposes.**

### Install required python modules
Use `pip` to install modules from the requirements file:
```
python -mpip install --user -r requirements.txt
```

### Get fingerprints from HTTPS server
#### Generate a self-signed key and cert for the HTTPS server
Use `openssl` to generate the private key and certificate:
```
$ openssl req -x509 -newkey rsa:2048 -keyout /tmp/server.key -out /tmp/server.crt -days 365 -nodes
.......+....+..+......+++++++++++++++++++++++++++++++++++++++*............+...+..........+.........+++++++++++++++++++++++++++++++++++++++*......+.+........+..........+.....+.........+.......+...+...........+....+......+..+....+...........+..........+..+..........+.....+.+......+.....+.++++++
.....+...........+.+...........+..........+.................+......+..........+..+.......+++++++++++++++++++++++++++++++++++++++*............+.....+.........+......+.......+...+............+..+.+..............+.........+++++++++++++++++++++++++++++++++++++++*....+.......+........+....+..++++++
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [XX]:AU
State or Province Name (full name) []:
Locality Name (eg, city) [Default City]:
Organization Name (eg, company) [Default Company Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (eg, your name or your server's hostname) []:localhost
Email Address []:
```

Verify the newly created `/tmp/server.key` and `/tmp/server.crt` exist.

#### Start the server
Run the server script to listen for connections locally on port 4433:
```
python server.py --key /tmp/server.key --cert /tmp/server.crt --host 127.0.0.1 --port 4433
```

#### Make a HTTPS request
Visit https://localhost:4433/tls in your browser and accept the warning (due to using a self-signed certificate). Alternatively, use `curl --insecure/-k`.

**NOTE:** Notice that fingerprints will generally differ for each client (e.g. `curl` and `firefox`), and some clients even purposefully randomise their handshake data. Different versions of clients are also likely to affect fingerprints. 

### Example usage with curl and jq
Get ja4 fingerprint only:
```
$ curl -s -k https://localhost:4433/tls | jq '.tls_fingerprints.ja4'
"t13d4213h1_171bc101b036_5f0018e59d20"
```
Get ja3 and ja4 fingerprints only:
```
$ curl -s -k https://localhost:4433/tls | jq '.tls_fingerprints.ja3,.tls_fingerprints.ja4'
"160803d3ae5b823f4d69b160c1f65837"
"t13d4213h1_171bc101b036_5f0018e59d20"
```
Get all fingerprints:
```
$ curl -s -k https://localhost:4433/tls | jq '.tls_fingerprints'
{
  "ja3_r": "771,4866-4867-4865-4868-49196-49200-52393-52392-49325-49195-49199-49324-49187-49191-49162-49172-49161-49171-157-49309-156-49308-61-60-53-47-163-159-52394-49311-162-158-49310-107-106-103-64-57-56-51-50-255,0-11-10-16-22-23-49-13-43-45-51-27-21,29-23-30-25-24-256-257-258-259-260,0-1-2",
  "ja3": "160803d3ae5b823f4d69b160c1f65837",
  "ja4_r": "t13d4213h1_002f,0032,0033,0035,0038,0039,003c,003d,0040,0067,006a,006b,009c,009d,009e,009f,00a2,00a3,00ff,1301,1302,1303,1304,c009,c00a,c013,c014,c023,c027,c02b,c02c,c02f,c030,c09c,c09d,c09e,c09f,c0ac,c0ad,cca8,cca9,ccaa_000a,000b,000d,0015,0016,0017,001b,002b,002d,0031,0033_0403,0503,0603,0807,0808,0809,080a,080b,0804,0805,0806,0401,0501,0601,0303,0301,0402,0502,0602,0302,0203,0201,0202",
  "ja4": "t13d4213h1_171bc101b036_5f0018e59d20",
  "ja4_ro": "t13d4213h1_1302,1303,1301,1304,c02c,c030,cca9,cca8,c0ad,c02b,c02f,c0ac,c023,c027,c00a,c014,c009,c013,009d,c09d,009c,c09c,003d,003c,0035,002f,00a3,009f,ccaa,c09f,00a2,009e,c09e,006b,006a,0067,0040,0039,0038,0033,0032,00ff_0000,000b,000a,0010,0016,0017,0031,000d,002b,002d,0033,001b,0015_0403,0503,0603,0807,0808,0809,080a,080b,0804,0805,0806,0401,0501,0601,0303,0301,0402,0502,0602,0302,0203,0201,0202",
  "ja4_o": "t13d4213h1_39839e6b3fa6_f26b8825e7be"
}
```
Get cipher suites only:
```
$ curl -s -k https://localhost:4433/tls | jq '.tls_data.cipher_suites'
[
  "1302",
  "1303",
  "1301",
  "1304",
  "c02c",
  "c030",
  "cca9",
  "cca8",
  "c0ad",
  "c02b",
  "c02f",
  "c0ac",
  "c023",
  "c027",
  "c00a",
  "c014",
  "c009",
  "c013",
  "009d",
  "c09d",
  "009c",
  "c09c",
  "003d",
  "003c",
  "0035",
  "002f",
  "00a3",
  "009f",
  "ccaa",
  "c09f",
  "00a2",
  "009e",
  "c09e",
  "006b",
  "006a",
  "0067",
  "0040",
  "0039",
  "0038",
  "0033",
  "0032",
  "00ff"
]
```
Get TLS data only:
```
{
  "protocol_version": "0303",
  "cipher_suites": [
    "1302",
    "1303",
    "1301",
    "1304",
    "c02c",
    "c030",
    "cca9",
    "cca8",
    "c0ad",
    "c02b",
    "c02f",
    "c0ac",
    "c023",
    "c027",
    "c00a",
    "c014",
    "c009",
    "c013",
    "009d",
    "c09d",
    "009c",
    "c09c",
    "003d",
    "003c",
    "0035",
    "002f",
    "00a3",
    "009f",
    "ccaa",
    "c09f",
    "00a2",
    "009e",
    "c09e",
    "006b",
    "006a",
    "0067",
    "0040",
    "0039",
    "0038",
    "0033",
    "0032",
    "00ff"
  ],
  "extensions": [
    "0000",
    "000b",
    "000a",
    "0010",
    "0016",
    "0017",
    "0031",
    "000d",
    "002b",
    "002d",
    "0033",
    "001b",
    "0015"
  ],
  "server_name": "6c6f63616c686f7374",
  "ec_point_formats": [
    "00",
    "01",
    "02"
  ],
  "supported_groups": [
    "001d",
    "0017",
    "001e",
    "0019",
    "0018",
    "0100",
    "0101",
    "0102",
    "0103",
    "0104"
  ],
  "alpn": [
    "6832",
    "687474702f312e31"
  ],
  "signature_algorithms": [
    "0403",
    "0503",
    "0603",
    "0807",
    "0808",
    "0809",
    "080a",
    "080b",
    "0804",
    "0805",
    "0806",
    "0401",
    "0501",
    "0601",
    "0303",
    "0301",
    "0402",
    "0502",
    "0602",
    "0302",
    "0203",
    "0201",
    "0202"
  ],
  "supported_versions": [
    "0304",
    "0303"
  ]
}
```

### Get the fingerprint from a pcap file
#### Use tcpdump to capture packets
Capture all packets on interface `enp6s0`, filter to only TCP with destination port 443, and save output to `/tmp/wow.pcap`:
```
$ sudo tcpdump -ni enp6s0 -w /tmp/wow.pcap 'tcp and port 443'
``` 

The pcap file:
```
$ ll /tmp/wow.pcap
-rw-r--r--. 1 elpy elpy 14M Jul 11 19:27 /tmp/wow.pcap
```

#### Capturing only TLS handshakes with tcpdump
This results in much smaller packet dumps and faster pcap searches.

Same as above example but only captures client TLS handshakes and saves output to `/tmp/handshakes.pcap`:
```
$ sudo tcpdump -ni enp6s0 -w /tmp/handshakes.pcap '(tcp[((tcp[12:1] & 0xf0) >> 2)+5:1] = 0x01) and (tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16)'
```

The pcap file (notice the size difference):
```
$ ll /tmp/handshakes.pcap
-rw-r--r--. 1 elpy elpy 294K Jul 11 19:29 /tmp/handshakes.pcap
```

#### Get all ja4 TLS client fingerprints from pcap file
Get count of total fingerprints:
```
$ python pcap.py --file /tmp/wow.pcap | wc -l
81

$ python pcap.py --file /tmp/handshakes.pcap | wc -l
401
```

Get counts of unique fingerprints:
```
$ python pcap.py --file /tmp/wow.pcap | sort | uniq -c | sort -nr
     39 t13d1714h1_5b57614c22b0_11c45d407049
     17 t13d1714h1_5b57614c22b0_037af2079008
      8 t13d1516h1_8daaf6152771_9b887d9acb53
      7 t13d1715h1_5b57614c22b0_061b66399db3
      6 t13d1516h1_8daaf6152771_e5627efa2ab1
      2 t13d1517h1_8daaf6152771_6cdcb247c39b
      1 t13d421100_171bc101b036_6a5408a479dd
      1 t12d380700_f2df0cc82b44_49449f310df7

$ python pcap.py --file /tmp/handshakes.pcap | sort | uniq -c | sort -nr
    263 t13d1714h1_5b57614c22b0_11c45d407049
    106 t13d1516h1_8daaf6152771_e5627efa2ab1
     18 t13d1715h1_5b57614c22b0_061b66399db3
     12 t13d1714h1_5b57614c22b0_037af2079008
      1 t13d1515h1_8daaf6152771_f37e75b10bcc
      1 t12d1409h1_c866b44c5a26_e70312a1ce2c
```

Time taken to print all fingerprints:
```
$ \time -- python pcap.py --file /tmp/wow.pcap 1> /dev/null:
0.05user 0.04system 0:00.10elapsed 99%CPU (0avgtext+0avgdata 57600maxresident)k
0inputs+0outputs (0major+24605minor)pagefaults 0swaps

$ \time -- python pcap.py --file /tmp/handshakes.pcap 1>/dev/null
0.05user 0.01system 0:00.06elapsed 98%CPU (0avgtext+0avgdata 16692maxresident)k
0inputs+0outputs (0major+2395minor)pagefaults 0swaps
```
