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
from stix.core import STIXPackage
import argparse, sys, os, shutil, re, socket
import TARDIS


if __name__=="__main__":
	
	#Get options from the command line...
	parser = argparse.ArgumentParser(description='TARDIS Threat Parser')
	parser.add_argument('-f', help='STIX File', dest='file', required=True)
	parser.add_argument('-i', help='Vulnerable IP', dest='ip', required=True)
	parser.add_argument('-d', help='Vulnerable DNS Hostname', dest='hostname')
	args = parser.parse_args()
	
	file=args.file
	sourceIP = args.ip
	sourceHost = args.hostname
	cve=''
	vulnObject=''
	if not os.path.exists(file):
		print file + " does not exist."
		sys.exit()
	
	if (sourceHost is None):
		try:
			result = socket.gethostbyaddr(sourceIP)
			sourceHost = result[0]
		except:
			sourceHost = ""
	if (len(sourceHost) > 0):
		print ("File: " + file)
		print ("IP:   " + sourceIP)
		print ("Host: " + sourceHost)
		
		if os.path.exists('Results'):
			shutil.rmtree('Results')
		directory='Results'
		#Create results directory to store the raw output
		if not os.path.exists(directory):
			os.makedirs(directory)
		if not os.path.exists(directory + '/' + sourceIP):
			os.makedirs(directory + '/' + sourceIP)
		
		#Get CVE from STIX
		stix_package = STIXPackage.from_xml(file)
		for target in stix_package.exploit_targets:
			for vuln in target.vulnerabilities:
				print "CVE: " + vuln.cve_id
				print "DESC:" + str(vuln.description)
				vulnObject=str(vuln.description)
				cve = vuln.cve_id
		if len(cve) > 0:
			if len(vulnObject) > 0:
				if not os.path.exists('VulnXML/' + vuln.cve_id + '.xml'):
					shutil.copyfile(file,'VulnXML/' + vuln.cve_id + '.xml')
				numResults=TARDIS.main(cve, vulnObject, sourceIP, sourceHost)
			else:
				print("Description missing from Exploit Target")
		else:
			print("CVE Missing from STIX File")

	else:
		print ("Unable to resolve hostname, please provide one with -d option")