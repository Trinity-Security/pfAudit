package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strings"
)

func checks(text string, repFile *os.File) {
	//Flatten xml
	stripText := strings.Replace(text, "\n", "", -1)
	stripText = strings.Replace(stripText, "\t", "", -1)
	//checks
	//1
	if strings.Contains(text, "<name>admin</name>") {
		repFile.WriteString("\n[I] Default admin username has not been changed.\n\t[*] String: <name>admin</name>\n")
	}
	//2
	if strings.Contains(text, "<protocol>http</protocol>") {
		repFile.WriteString("\n[I] Admin UI exposed over HTTP.\n\t[*] String: <protocol>http</protocol>\n")
	}
	//3
	if !strings.Contains(text, "<crypto_hardware>aesni</crypto_hardware>") {
		repFile.WriteString("\n[I] AES-NI is not enabled.\n\t[*] String missing: <crypto_hardware>aesni</crypto_hardware>\n")
	}
	//4
	acbCheck := regexp.MustCompile(`<acb>(.*)</acb>`)
	result := acbCheck.FindString(stripText)
	if strings.Contains(result, "<enable></enable>") {
		repFile.WriteString("\n[I] Auto configuration backup is not enabled.\n\t[*] String: <enable></enable>\n")
	}
	//5
	dnsCheck := regexp.MustCompile(`<system>(.*)</system>`)
	result = dnsCheck.FindString(stripText)
	if strings.Count(result, "</dnsserver>") < 2 {
		repFile.WriteString("\n[I] Only one DNS server has been specific in the system settings.\n\t[*] String: " + result + "\n")
	}
	//6
	syslogCheck := regexp.MustCompile(`<syslog>(.*)</syslog>`)
	result = syslogCheck.FindString(stripText)
	if strings.Count(result, "<remoteserver>") < 1 {
		repFile.WriteString("\n[I] Not remote syslog server has been specified.\n\t[S] String: " + result + "\n")
	}
	//7
	if strings.Contains(text, "<ipv6allow></ipv6allow>") {
		repFile.WriteString("\n[I] IPv6 is allowed and enabled but may not be required.\n\t[*] String: <ipv6allow></ipv6allow>\n")
	}
	//8
	if strings.Contains(text, "<ispool></ispool>") {
		repFile.WriteString("\n[I] An NTP server has not been configured.\n\t[S]String: <ispool></ispool>\n")
	}
	//9
	if !strings.Contains(text, "<scrubrnid>enabled</scrubrnid>") {
		repFile.WriteString("\n[I] Packet Filter IP Random ID generation not enabled.\n\t[*] String missing: <scrubrnid>enabled</scrubrnid>\n")
	}
	//10
	if strings.Contains(text, "<loginautocomplete></loginautocomplete>") {
		repFile.WriteString("\n[I] Autocomplete on pfSense web configurator web interface has not been disabled.\n\t[*] String: <loginautocomplete></loginautocomplete>\n")
	}
	//11
	if strings.Count(text, "<snmpd>") > 0 {
		snmpCheck := regexp.MustCompile(`<snmp>(.*)</snmp>`)
		result = snmpCheck.FindString(stripText)
		if strings.Contains(result, "<rocommunity>public</rocommunity>") && strings.Contains(result, "<enable></enable>") {
			repFile.WriteString("\n[I] Public SNMP community string defined.\n\t[*] String: <rocommunity>public</rocommunity>\n")
		}
	}
	//12
	if strings.Count(text, "<unbound>") > 0 {
		unboundCheck := regexp.MustCompile(`<unbound>(.*)</unbound>`)
		result = unboundCheck.FindString(stripText)
		if strings.Count(result, "<enable></enable>") > 0 && strings.Count(result, "<enablessl></enablessl>") < 1 {
			repFile.WriteString("\n[I] SSL/TLS connections are not enabled for pfSense Unbound DNS server.\n\t[*] String: " + result + "\n")
		}
	}
	//13
	if !strings.Contains(text, "<type>ldap</type>") {
		repFile.WriteString("\n[I] LDAP authentication is not enabled.\n\t[*] String missing: <type>ldap</type>\n")
	}
	//14
	if strings.Contains(text, "<ldap_port>389</ldap_port>") {
		repFile.WriteString("\n[I] LDAP authentication without TLS is enabled.\n\t[*] String: <ldap_port>389</ldap_port>\n")
	}
	//15
	if strings.Count(text, "<smtp>") > 0 {
		smtpCheck := regexp.MustCompile(`<smtp>(.*)</smtp>`)
		result = smtpCheck.FindString(stripText)
		if strings.Count(result, "@") > 0 && strings.Count(result, "<ssl></ssl>") < 1 {
			repFile.WriteString("\n[I] SSL/TLS is not enabled for SMTP emails.\n\t[*] String: " + result + "\n")
		}
	}
	//16
	if strings.Contains(text, "<quietlogin></quietlogin>") {
		repFile.WriteString("\n[I] Logging of webConfigurator successful logins is disabled.\n\t[*] String: <quietlogin></quietlogin>\n")
	}
	//17
	if strings.Count(text, "<ssh>") > 0 {
		sshCheck := regexp.MustCompile(`<ssh>(.*)</ssh>`)
		result = sshCheck.FindString(stripText)
		if strings.Count(result, "<sshdkeyonly>") < 1 && strings.Count(result, "<enable>enabled</enable>") > 0 {
			repFile.WriteString("\n[I] SSH access to the system is enabled without keys (password only).\n\t[*] String: " + result + "\n")
		}
	}
	//18
	if !strings.Contains(text, "<hasync>") {
		repFile.WriteString("\n[I] High availability configuration sync to a remote pfSense instance is not enabled.\n\t[*] String missing: <hasync>\n")
	}
	//19
	if strings.Count(text, "<firmware>") > 0 {
		firmwareCheck := regexp.MustCompile(`<firmware>(.*)</firmware>`)
		result = firmwareCheck.FindString(stripText)
		if strings.Count(result, "<disablecheck></disablecheck>") > 0 {
			repFile.WriteString("\n[I] Firmware update check on the dashboard has been disabled.\n\t[*] String: " + result + "\n")
		}
	}
	//20
	if !strings.Contains(text, "<dns2host>") {
		repFile.WriteString("\n[I] Secondary DNS server has not been specified.\n\t[*] String missing: <dns2host>\n")
	}
	//21
	if strings.Contains(text, "<sshguard_threshold></sshguard_threshold>") {
		repFile.WriteString("\n[I] SSH login bruteforce protection best practices has not been enabled, including threshold and blocktime.\n\t[*] String: <sshguard_threshold></sshguard_threshold>\n")
	}	
	//22
	if strings.Contains(text, "<any></any>") {
		repFile.WriteString("\n[I] ANY ANY Firewall rules detected, each should be reviewed for validity.\n\t[*] String: <any></any>\n")
	}
	//23
	if strings.Contains(text, "<local-port>53</local-port>") {
		repFile.WriteString("\n[I] Internal DNS is not configured to use DNS over TLS.\n\t[*] String: <local-port>53</local-port>\n")
	}	
	//24
	if strings.Count(text, "<openvpn-server>") > 0 {
		openvpnCheck := regexp.MustCompile(`<openvpn-server>(.*)</openvpn-server>`)
		result = openvpnCheck.FindString(stripText)
		if strings.Count(result, "<authmode>Local Database</authmode>") > 0 {
			repFile.WriteString("\n[I] OpenVPN configured to use local database and not a centralised account management platform.\n\t[*] String: <authmode>Local Database</authmode>\n")
		}
		if strings.Count(result, "<digest>SHA1</digest>") > 0 {
			repFile.WriteString("\n[I] OpenVPN configured to use deplicated SHA-1 digest.\n\t[*] String: <digest>SHA1</digest>\n")
		}
		if strings.Count(result, "<dns_server2></dns_server2>") > 0 {
			repFile.WriteString("\n[I] OpenVPN is only configured with a single DNS server.\n\t[*] String: <dns_server2></dns_server2>\n")
		}
		if strings.Count(result, "<mode>server_tls_user</mode>") < 1 {
			repFile.WriteString("\n[I] OpenVPN is not configured to use certificates with user authentication.\n\t[*] String missing: <mode>server_tls_user</mode>\n")
		}		
	}
	//25
	if !strings.Contains(text, "<crypto_hardware>aesni</crypto_hardware>") {
		repFile.WriteString("\n[I] Cryptographic acceleration is not enabled which may reduce throughput and increase load on the system.\n\t[*] String missing: <crypto_hardware>aesni</crypto_hardware>\n")
	}
}

func main() {

	pffilePtr := flag.String("file", "", "\nFilename to parse (XML). (Required)\nExample: pfaudit -file backup.xml\n\n")
	flag.Parse()

	if *pffilePtr == "" {
		flag.PrintDefaults()
		os.Exit(0)
	}

	content, err := ioutil.ReadFile(*pffilePtr)
	if err != nil {
		log.Fatal(err)
	}
	//Starting here
	fmt.Println("\n\n[I] Beginning Scan. -= PfAudit by Trinity Security (www.trinitysecurity.au) =-")

	//Create report file
	repFile, err := os.Create("pfReport.txt")
	if err != nil {
		fmt.Println(err)
		return
	}
	_, err = repFile.WriteString("[I] pfSense Firewall Auditor - by Trinity Security\n\n")
	if err != nil {
		fmt.Println(err)
		repFile.Close()
		return
	}

	//Run checks against XML
	text := string(content)
	checks(text, repFile)

	//Finished
	fmt.Println("\n[I] Scan complete. Please review pfReport.txt for findings.\n\n")
}
