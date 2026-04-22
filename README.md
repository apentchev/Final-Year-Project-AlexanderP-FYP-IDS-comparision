FYP — Comparing Signature-Based IDS with ML-Based Anomaly Detection
BSc Computer Security and Forensics — University of Greenwich  
Student: Alexander Pentchev (001239049)  




\ Repository Contents



**01\_extract\_features.py** - Extracts 34 features from Zeek conn.log files; applies labels; balances dataset 



**02\_random\_forest.py** - Trains and evaluates Random Forest classifier 



**03\_isolation\_forest.py** - Trains and evaluates Isolation Forest anomaly detector 



**fyp\_gui.py** - GUI launcher for the ML pipeline 


Requirements:
- Windows OS
- Python 3.8 or higher in

How to Run:

To run the GUI:
1. Make sure the Zeek session folders are in the same folder as the .py files
2. Double-click run_fyp_gui.bat
3. The first run will take 2-3 minutes to install dependencies
4. GUI opens and runs can be started
5. Add sessions using the GUI or let it auto-load from `01\_extract\_features.py` 
6. click on "Run All Steps" to process the complete pipeline

If you get "Python not found":
- Download Python from https://www.python.org/downloads/
- During installation, CHECK the box "Add Python to PATH"
- Restart your computer
- Try again

IMPORTANT: Make sure your session files are in the same folder as the .py files!

Dependencies


```bash

pip install pandas numpy matplotlib seaborn scikit-learn

```

References



Two GitHub repositories were consulted for structural guidance:

\- Western-OC2-Lab/Intrusion-Detection-System-Using-Machine-Learning (ML pipeline structure)
https://github.com/Western-OC2-Lab/Intrusion-Detection-System-Using-Machine-Learning

\- SecurityNik/Data-Science-and-ML (Zeek processing patterns)
https://github.com/SecurityNik/Data-Science-and-ML



