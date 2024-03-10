# Intro

## Carrer

* Junior Security Analyst - Tier1 - Triage
>	- Monitors the network traffic logs and events
>	- Works on the tickets, closes the alerts
>	- Perform basic investigations and mitigations

* Security Operations Analyst - Tier 2 - Incident Responder
	- Focuses on deeper investigations, analysis and remediation
	- Proactively hunts for adversaries
	- Monitors and resolves more complex alerts

* Security Operations Analyst - Tier 3 - Threat Hunter
	- Works on more advanced investigations
	- Performs advanced threat hunting and adversary research
	- Malware reversing

## Important Places for getting update

* [__Feedly__](https://feedly.com/i/welcome) and Twiter

* __Open-source databases__ out there like [__AbuseIPDB__](https://www.abuseipdb.com), [__Cisco Talos Intelligence__](https://talosintelligence.com). 

  where you can perform a reputation and location check for the IP address.

## Preparation and Prevention

* Prevention methods include gathering intelligence data on the latest threats, threat actors, and their `TTPs` (`Tactics, Techniques, and Procedures`).

	> Firewall signature update
	
	> Pacting vulna in exsisting systems
	
	> Block and Allow list of applications, emails and IPs


##
##
# Pyramid of Pain

1. Hash Values (Trivial)
2. IP Address (Easy)
3. Domain Names (Simple)
4. Host Artifacts (Annoying)
5. Network Artifacts (Annoying)
6. Tools (Challenging)
7. TTPs (Tough)


## Hash Values -

* __MD5__ (__Message Digest__, defined by RFC 1321)
* __SHA-1__ (__Secure Hash Algorithm 1__, defined by RFC 3174) 
* __The SHA-2__ (__Secure Hash Algorithm 2__)

	Security professionals usually use the __hash values__ to gain __insight__ into a specific __malware sample__, a _malicious_ or a _suspicious file_, and as a way to uniquely identify and reference the malicious artifact.

	Check out [The DFIR Report](https://thedfirreport.com/) and [FireEye Threat Research Blogs](https://www.fireeye.com/blog/threat-research.html) if you’re interested in seeing an example.


	Various online tools can be used to do hash lookups like [VirusTotal](https://www.virustotal.com/gui/) and [Metadefender Cloud - OPSWAT](https://metadefender.opswat.com/?lang=en).

	Detecting by hash values is simple, but if an attacker changes a single bit of the file then the hash value will change and detecting is hard


## IP Address -

- We can simply __block the IP address__ of the __incoming connection__ and protect our env.

- __Challenging__ to successfully carry out __IP blocking__ if attackers are using __Fast Flux__.

    Attacker can make this IP address blocking more difficult by using the Flast Flux technique.


### Fast Flux -
When __one domain__ will have __multiple A or AAAA__ records against it, which is constantly changing.


## Domain Names -

We can also __block__ the __connections using domain name__, as these are simple that an IP address will be mapped against a Domain name.

### __What is `Punycode`?__ 

	As per Wandera, "Punycode is a way of converting words that cannot be written in ASCII, into a Unicode ASCII encoding."

What you saw in the URL above is `adıdas.de` which has the Punycode of `http://xn--addas-o4a.de/`

We can see the actual website the shortened link is redirecting you to by appending "+" to it 


### Sandboxing any suspicious file with Any.run

We can easily see `HTTP requests` and `Connections` and `DNS requests` from the mailicious file easily


## Host Artifacts -

Host artifacts are the __traces or observables that attackers leave__ on the system, such as `registry values`, `suspicious process execution`, `attack patterns` or `IOCs` (Indicators of Compromise), `files dropped` by malicious applications, or anything exclusive to the current threat.


### Tools -

[Any.run](https://www.any.run) and [VirusTotal](https://www.virustotal.com/gui/)


## Network Artifacts -

> A network artifact can be a `user-agent string`, `C2 information`, or `URI patterns` `followed` by the `HTTP POST` requests.

> An attacker might use a User-Agent string that hasn’t been observed in your environment before or seems out of the ordinary. The User-Agent is defined by RFC2616 as the request-header field that contains the information about the user agent originating the request.

> Network artifacts `can be detected` in `Wireshark PCAPs` (file that contains the packet data of a network) by using a network protocol analyzer such as `TShark` or `exploring IDS `(Intrusion Detection System) `logging` from a source such as Snort.


## Tools -

Attackers would use the utilities to create `malicious macro documents` (maldocs) for `spearphishing` attempts, a `backdoor` that can be used to establish `C2` (`Command and Control Infrastructure`), any custom .EXE, and .DLL files, payloads, or password crackers.

`MalwareBazaar` and `Malshare` are good resources to provide you with access to the samples, malicious feeds, and YARA results - these all can be very helpful when it comes to threat hunting and incident response. 

`Fuzzy hashing` is also a strong weapon against the attacker's tools. Fuzzy hashing helps you to perform similarity analysis - `match two files with minor differences` based on the fuzzy hash values. One of the examples of fuzzy hashing is the usage of `SSDeep`; on the `SSDeep` official website, you can also find the complete explanation for fuzzy hashing. 

