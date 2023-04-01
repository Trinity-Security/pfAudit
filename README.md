# pfAudit
pfSense Audit Tool

### About
pfAudit is a simple pfSense configuration analyser, looking for common security misconfigurations and deployment weaknesses.

### Getting started
1. Install (Go)[https://go.dev/]
2. Clone the repo
   ```sh
   git clone https://github.com/Trinity-Security/pfAudit.git
   ```
3. Execute
   ```sh
    go run pfAudit -file backup.xml
   ```
4. Read the results in pfReport.txt