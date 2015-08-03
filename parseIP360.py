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


import xml.etree.ElementTree as ET
import argparse, sys, os, shutil, re
import TARDIS


if __name__=="__main__":
	#os.chdir('C:\\TARDIS')
	os.chdir('/opt/tardis')

	#Get options from the command line...
	parser = argparse.ArgumentParser(description='TARDIS Threat Parser')
	parser.add_argument('-f', help='IP360 XML3 File', dest='file', required=True)
	args = parser.parse_args()
	
	#File must be in the Tripwire IP360 XML3 format
	file=args.file
	
	try:
		tree = ET.parse(file)
		root = tree.getroot()
	except:
		sys.exit("Not a valid XML file, use IP360 XML3 audit output")
	
	#Clear results folder to have a fresh starting point...
	if os.path.exists('Results'):
		shutil.rmtree('Results')
	
	numHosts=0
	
	for host in root.findall("./audit/hosts/host"):
		numHosts=numHosts+1
		directory='Results'
		#Create results directory to store the raw output
		if not os.path.exists(directory):
			os.makedirs(directory)
		#Get IP address to run threat search against
		for ip in host.findall("./ip"):
			sourceIP=ip.text
			#We like individual directories per IP
			if not os.path.exists(directory + '/' + sourceIP):
				os.makedirs(directory + '/' + sourceIP)
		for hostname in host.findall("./dnsName"):
			sourceHost=hostname.text
		for vulnerability in host.findall("./vulnerabilities/vulnerability"):
			internalVulnerabilityID=vulnerability.get('id')
			vulnName=internalVulnerabilityID
			#Convert internal vulnerability ID into a human readable name
			for line in open("idmap.config"):
				if internalVulnerabilityID in line:
					vulnName = re.sub('\d+\:', '', line)
					vulnName = re.sub('(\r\n|\r|\n)', '', vulnName)
					internalVulnerabilityID = vulnName
			numResults=TARDIS.main(vulnName, sourceIP, sourceHost)
	if numHosts<1:
		sys.exit("Not a valid XML file, use IP360 XML3 audit output")