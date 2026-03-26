# Project Summary – Log File Analyzer for Intrusion Detection

In this project, I developed a Python-based tool to analyze Apache and SSH log files for detecting suspicious activities.

First, I created and used sample log files to simulate real-world scenarios. I wrote a Python script that reads these log files and extracts important information such as IP addresses, timestamps, request types, and status codes using regular expressions.

I used pandas to organize and analyze the log data efficiently. Based on this data, I implemented different detection techniques:

* Identified brute force attacks by detecting multiple failed login attempts from the same IP
* Detected possible DoS attacks by analyzing high request rates from a single IP within a short time
* Identified scanning behavior by checking multiple URL access patterns

I also included a feature to cross-check suspicious IP addresses with a blacklist to detect known malicious sources.

To better understand the data, I used matplotlib and seaborn to generate visualizations such as request distribution, traffic over time, and suspicious IP comparisons.

Finally, I exported the results into JSON and CSV formats and generated a graph report showing the analysis results.

Through this project, I learned how log analysis helps in identifying security threats and how Python can be used to build basic intrusion detection systems.
