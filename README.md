# I Know Who You Scanned Last Summer: Mapping the Landscape of Internet-Wide Scanners
This README provides details on the pipeline used in the according paper.


## Provided Dataset
In the folder *data/20240131_demo/*, we provide a short and anonymized data set.
We only provide the first 100.000 entries of our original dataset to reduce the file size, if you are interested in the full dataset, please contact the authors.
Additionally, we removed all data tracing the real scanner... 
We see this step as necessary to protect the information of the individual.
However, due to the anonymization, you will not be able to execute all analytics explained below.
For each step, we will provide additional information on the limitations.

For complete reference, you can find the anonymization of our dataset in [anonymize-data.py](code/anonymize-data.py).


## Preparation of the Dataset
The first step of our pipeline is the calculation of helper variables for more efficient analysis afterwards.
The file [prepare-data.py](code/prepare-data.py) contains all the procedures.


### Identification of Tools
The tools are mostly identified through TCP/IP header information.
In the code, you can find all the detailed calculations.
However, some will not work correctly on the anonymized dataset.


### Identification of Organizations
The anonymized dataset does not contain any information of *ipinfo*.
In our pipeline, this data is collected before importing the data to Logstash, as data can change over time.
Therefore, we provide the table [Organization Identification](keywords_table.md) with all the relevant content we identified.
The table shows all identified organizations and their hostname/company name/AS name by which we identified them.
The keywords used in the search were: scan, probe, measurement, research, security, university, education, institute.
For organizations found through manual analysis, we added a remark. 
We found these organizations mainly because of their high traffic load.


## Process Data
The file [processe-data.py](code/process-data.py) contains some examples for our evaluation.
