# AEGIS Dataset - Research Papers Summary

## Datasets Referenced

### 1. CICIDS 2017 (Canadian Institute of Cybersecurity)
- **Source:** https://www.unb.ca/cic/datasets/ids-2017.html
- **Kaggle:** https://www.kaggle.com/datasets/shadman1028/cicids2017-official-flow-feature-csv-files
- **Records:** 2,830,743
- **Features:** 84 network flow features
- **Attacks:** Brute Force FTP/SSH, DoS, Heartbleed, Web Attack, Infiltration, Botnet, DDoS
- **Attack Categories:** 14 types (Benign, SSH-Patator, FTP-Patator, DoS Hulk, DoS GoldenEye, DoS Slowhttptest, Heartbleed, Web Attack Brute Force, Web Attack SQL Injection, Web Attack XSS, Infiltration, Bot, PortScan, DDoS)

### 2. NSL-KDD (Network Intrusion Detection)
- **Source:** https://www.unb.ca/cic/datasets/nsl.html
- **Features:** 41 features + 1 label
- **Attack Categories:** DoS, Probe, R2L, U2R
- **Attack Types:** back, land, neptune, pod, smurf, teardrop, mailbomb, apache2, ipsweep, nmap, portsweep, satan, ftp_write, guess_passwd, buffer_overflow, rootkit, etc.

### 3. UNSW-NB15 (University of New South Wales)
- **Source:** https://research.unsw.edu.au/projects/unsw-nb15-dataset
- **Records:** 2,540,044
- **Features:** 49 features
- **Attacks:** Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms

### 4. FADE Dataset (Firewall Attack Detection Extractions)
- **Source:** IEEE DataPort
- **Records:** 50 million entries
- **Features:** 8 attack categories with balanced benign/malicious traffic
- **Format:** CSV + Parquet

### 5. OWASP ModSecurity Dataset
- **Source:** Zenodo (https://zenodo.org/records/17178461)
- **Records:** 147,205 blocked requests over 30 days
- **Attacks:** SQL Injection, XSS, LFI, RFI, Command Injection, PHP Injection, Scanner Probes

### 6. Web Application Payloads Dataset (Kaggle)
- **Source:** https://www.kaggle.com/datasets/cyberprince/web-application-payloads-dataset

### 7. HttpParamsDataset
- **Source:** https://github.com/Morzeux/HttpParamsDataset
- **Records:** 3100+ values
- **Attacks:** SQL Injection (10,852), XSS (532), Command Injection (89), Path Traversal (290)

### 8. SecureAI HTTP Attack Requests
- **Source:** Hugging Face (SecureAI-SE/http-attack-requests)
- **Classes:** normal, sqli, xss, ssrf, ssti, lfi, traversal

### 9. JailbreakLLMs Dataset (CCS 2024)
- **Source:** https://github.com/verazuo/jailbreak_llms
- **Records:** 15,140 prompts (1,405 jailbreak prompts)
- **Sources:** Reddit, Discord, websites, open-source datasets

### 10. JailbreakDB
- **Source:** Hugging Face (youbin2014/JailbreakDB)
- **Records:** 6.6M jailbreak + 5.7M benign prompts

### 11. Bordair Multimodal Attack Dataset
- **Source:** Hugging Face (Bordair/bordair-multimodal)
- **Records:** 503,358 labeled samples (251,782 attack + 251,576 benign)
- **Coverage:** Cross-modal, multi-turn, adversarial suffix, jailbreak template, indirect injection, tool manipulation, agentic attacks

## Research Papers Cited

1. "Intrusion detection evaluation dataset (CIC-IDS2017)" - Sharafaldin et al., 2018
2. "UNSW-NB15: a comprehensive data set for network intrusion detection systems" - Moustafa & Slay, 2015
3. "The evaluation of Network Anomaly Detection Systems" - Moustafa & Slay, 2016
4. "A Comprehensive Study on CIC-IDS2017 Dataset" - Khan et al., 2024
5. "Detection of SQL Injection, XSS, and Command Injection Attacks Using SVM, RF, and XGBoost" - Widodo et al., 2026
6. "Do Anything Now: Characterizing and Evaluating In-The-Wild Jailbreak Prompts" - Shen et al., CCS 2024
7. "A Thirty-Day Dataset of Malicious HTTP Requests Blocked by OWASP ModSecurity" - Lucz & Forstner, 2025
8. "DarkSegments_IDS" - Almaleki, 2026
9. "FADE: Firewall Attack Detection Extractions" - IEEE DataPort
10. "SoK: Taxonomy and Evaluation of Prompt Security in LLMs" - Hong et al., 2025

## Feature Engineering Sources

### From CICIDS 2017 (84 features)
- Flow Duration, Total Fwd/Bwd Packets
- Packet Length Statistics (Min, Max, Mean, Std)
- Flag Counts (SYN, ACK, FIN, RST, PSH, URG)
- Inter-arrival Time Statistics
- Backward Packet Rate
- Flow Bytes/s, Packets/s

### From NSL-KDD (41 features)
- duration, protocol_type, service, flag
- src_bytes, dst_bytes, land, wrong_fragment, urgent
- hot, num_failed_logins, logged_in, num_compromised
- root_shell, su_attempted, num_root, num_file_creations
- count, srv_count, serror_rate, rerror_rate
- same_srv_rate, diff_srv_rate
- dst_host_count, dst_host_srv_count
- dst_host_same_srv_rate, dst_host_diff_srv_rate

### From UNSW-NB15 (49 features)
- Basic features (6-18): dur, proto, state, spkts, dpkts, sbytes, dbytes, rate, sttl, dttl, sload, dload, sloss, dloss
- Content features (19-26): sjit, djit, swin, stcpb, dtcpb, dwin, tcprtt, synack, ackdat, smean, dmean
- Time features (27-35): trans_depth, response_body_len, ct_srv_src, ct_state_ttl, ct_dst_ltm, ct_src_dport_ltm, ct_src_state_ltm, ct_dst_src_ltm
- General features (36-47): is_ftp_login, ct_ftp_cmd, ct_flw_http_mthd, ct_src_ltm, ct_srv_dst, is_sm_ips_ports
- Attack categories: Normal, Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms

### Web Application Features (Custom for AEGIS)
- URL length, URL entropy
- Number of special characters
- Encoded character count
- SQL keyword presence
- JavaScript keyword presence
- Path traversal indicators
- Parameter count
- Max parameter length
- Body length, Body entropy
- HTML tag presence
- Script tag presence
- Header count
- User-Agent presence
- Content-Type anomalies
- Request rate per IP
- Session uniqueness
