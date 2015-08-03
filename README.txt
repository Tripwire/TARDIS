1) Execute 'python dependencies.py' to ensure all Python modules have been installed.  Continue when no errors are generated. 

2) Execute the sql_tardis.sql script to create the appropriate database and tables within MySQL. 

3) Edit the config.xml with the appropriate credentials of the MySQL Server, Splunk, or Elastic Search instances.  Update the log_source element with either 'splunk' or 'elastic_search', depending on the log repository being searched.  

4) Edit the dbColumns.config document.  This will be a mapping of STIX fields to the appropriate normalized column name in the log repository. Samples are provided for reference. 

5a) If using an IP360 scan output file, execute 'python parseIP360.py -f <xml_file>'
	-Note: Referenced STIX files are stored in the VulnXML directory.  A sample for ShellShock (98520.xml) is provided for reference. Any number of STIX documents can be referenced.  

5b) If using an individual STIX file, execute 'python parseSTIX.py -f <STIX_file> -i <ip_address> -d <hostname>
	-Note: the -d argument is optional.  If no hostname is provided, TARDIS will attempt to look up the hostname from the IP provided.  
	-Note: A copy of the STIX file is saved to the VulnXML directory using the CVE name as the filename.  