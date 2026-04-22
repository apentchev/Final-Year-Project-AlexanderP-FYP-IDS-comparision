\# FYP — Comparing Signature-Based IDS with ML-Based Anomaly Detection



\*\*BSc Computer Security and Forensics — University of Greenwich\*\*  

\*\*Student:\*\* Alexander Pentchev (001239049)  




\## Repository Contents



**01\_extract\_features.py** - Extracts 34 features from Zeek conn.log files; applies labels; balances dataset 



**02\_random\_forest.py** - Trains and evaluates Random Forest classifier 



**03\_isolation\_forest.py** - Trains and evaluates Isolation Forest anomaly detector 



**fyp\_gui.py** - GUI launcher for the ML pipeline 





\## How to Run



1\. Copy Zeek session folders from your capture VMs to this directory

2\. Run `python fyp\_gui.py` to launch the GUI

3\. Add sessions using the GUI or let it auto-load from `01\_extract\_features.py`

4\. Click "Run All Steps" to process the complete pipeline

NOTE: Make sure your session files are in the same folder as the .py files!

\## Dependencies



```bash

pip install pandas numpy matplotlib seaborn scikit-learn

```



\## References



Two GitHub repositories were consulted for structural guidance:

\- Western-OC2-Lab/Intrusion-Detection-System-Using-Machine-Learning (ML pipeline structure)
https://www.geeksforgeeks.org/machine-learning/random-forest-algorithm-in-machine-learning/

\- SecurityNik/Data-Science-and-ML (Zeek processing patterns)
https://github.com/SecurityNik/Data-Science-and-ML



