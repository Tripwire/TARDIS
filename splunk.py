'''
* Copyright (C) 2015 Tripwire, Inc.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
'''

import os, re
import splunklib.client as client
import splunklib.results as results
import xml.etree.ElementTree as ET

def getSplunkService():
	# Create a Splunk Service instance and log in 
	try:
		configFile = 'config.xml'
		tree = ET.parse(configFile)
		root = tree.getroot()
	except:
		sys.exit("Not a valid XML file")
	for settings in root.findall("./splunk"):
		for ip in settings.findall("./ip"):
			splunkHOST=ip.text
		for ip in settings.findall("./adminport"):
			splunkAdminPORT=ip.text
		for ip in settings.findall("./user"):
			splunkUser=ip.text
		for ip in settings.findall("./password"):
			splunkPass=ip.text
	
	service = client.connect(
		host=splunkHOST,
		port=splunkAdminPORT,
		username=splunkUser,
		password=splunkPass)
	return service
					
def searchVulnerability(searchString,vulnerability,sourceIP,sourceHost):
	directory='Results/'+sourceIP
	if not os.path.exists(directory):
		os.makedirs(directory)
	
	service = getSplunkService()
	
	# Get the collection of jobs
	jobs = service.jobs
	
	# Run a blocking search--search everything, return 1st 100 events
	kwargs_blockingsearch = {"exec_mode": "blocking"}
	
	# A blocking search returns the job's SID when the search is done
	job = jobs.create(searchString, **kwargs_blockingsearch)
	
	# Get properties of the job from Splunk
	#print "Search job properties"
	#print "Search job ID:        ", job["sid"]
	#print "The number of events: ", job["eventCount"]
	#print "The number of results:", job["resultCount"]
	#print "Search duration:      ", job["runDuration"], "seconds"
	#print "This job expires in:  ", job["ttl"], "seconds"
	
	# Prints a parsed, formatted CSV stream to a file
	
	numResults = job["resultCount"]
	if numResults=="0":
		return numResults
	else:
		
		result_stream = job.results(**{"output_mode": "json"})
		
		return result_stream
		
def searchVulnerabilityTimeRange(searchString,vulnerability,sourceIP,sourceHost,earliest,latest):
	directory='Results/'+sourceIP
	if not os.path.exists(directory):
		os.makedirs(directory)
	
	service = getSplunkService()
	
	# Get the collection of jobs
	jobs = service.jobs
	
	# Run a blocking search--search everything, return 1st 100 events
	kwargs_blockingsearch = {"exec_mode": "blocking", "earliest_time": earliest, "latest_time": latest,}
	
	# A blocking search returns the job's SID when the search is done
	job = jobs.create(searchString, **kwargs_blockingsearch)
	
	# Get properties of the job from Splunk
	#print "Search job properties"
	#print "Search job ID:        ", job["sid"]
	#print "The number of events: ", job["eventCount"]
	#print "The number of results:", job["resultCount"]
	#print "Search duration:      ", job["runDuration"], "seconds"
	#print "This job expires in:  ", job["ttl"], "seconds"
	
	# Prints a parsed, formatted CSV stream to a file
	
	numResults = job["resultCount"]
	if numResults=="0":
		return numResults
	else:
		result_stream = job.results(**{"output_mode": "json"})
		return result_stream
