# VirusTotal bulk hash checker

This is a frontend based VirusTotal bulk hash checker built in node.js and HTML that was designed for non-premium VirusTotal API users.
Due to API key limitations of 4 requests/minute, there's a sleep timer in between the scans per hashes.

![image](https://github.com/sscoconutree/VirusTotal-bulk-hash-checker/assets/59388557/1016b8df-db6b-4a2e-8140-b32a8bac4486)

<h3>How to use:</h3>

1. Edit ```app.js``` file and put your VirusTotal API key on the ```apikey``` field.
2. Have the files in a same folder and run the following: ```node app.js```
3. Open ```localhost:3000```
