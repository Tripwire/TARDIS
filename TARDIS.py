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

import re, csv, os, json
from collections import defaultdict
import ElasticSearchQuery
from elasticsearch import Elasticsearch
import findStixObservables
import socket, struct
import mysql.connector
import xml.etree.ElementTree as ET
import splunk
import dateutil.parser
import datetime

def ip2long(ip):
	if ip =='*':
		return 0
	return struct.unpack("!L", socket.inet_aton(ip))[0]

def long2ip(ip):
	return socket.inet_ntoa(struct.pack('!L', ip))

def getDBConnector():
	try:
		configFile = 'config.xml'
		tree = ET.parse(configFile)
		root = tree.getroot()
	except:
		sys.exit("Not a valid config XML file")
	for settings in root.findall("./db"):
		for dbip in settings.findall("./ip"):
			db_ip=dbip.text
		for dbname in settings.findall("./db_name"):
			db_name=dbname.text
		for dbuser in settings.findall("./user"):
			db_user=dbuser.text
		for dbpass in settings.findall("./password"):
			db_pass=dbpass.text
	cnx = mysql.connector.connect(user=db_user, password=db_pass, host=db_ip, database=db_name)
	return cnx

def writeElasticSearchResults(searchResults,vulnObject,sourceIP,vulnerability):
	for hit in searchResults['hits']['hits']:
		#check if vulnerability/asset combo exists in assetVulnerability Table
		es = Elasticsearch()
		doc = {
			'doc' : {
				vulnObject: 'YES',
				'CVE': vulnerability
			}
		}
		
		res = es.update(index=hit["_index"], id=hit["_id"], doc_type='logs', body=doc)
		cnx = getDBConnector()
		cursor = cnx.cursor()
		query = ("SELECT count(*) as count from attackInventory where victim_ip = '" + str(ip2long(sourceIP)) + "' and threat_id = '" + vulnerability + "' and attack_log = '" + hit["_source"]["message"] + "'")
		
		cursor.execute(query)
		for row in cursor:
			logCheck=row[0]
		cursor.close()
		if logCheck==0:
			#Write data to DB
			cursor = cnx.cursor()
			add_logInstance = ("INSERT INTO attackInventory "
								"(victim_ip, attacker_ip, attack_time, attack_log, threat_id) "
								"VALUES (%s, %s, %s, %s, %s)")
			try:
				attackerIP=ip2long(hit["_source"]["host"])
			except:
				attackerIP='0'
			logData = (ip2long(sourceIP), attackerIP, hit["_source"]["@timestamp"], hit["_source"]["message"], vulnerability)
			
			# Insert new entry
			cursor.execute(add_logInstance , logData )
			
			cnx.commit()
			cursor.close()
			cnx.close()

def getElasticSearchResults(searchResults):
	numResults="%d" % searchResults['hits']['total']
	return numResults

def main(vulnerability,vulnObject,sourceIP,sourceHost):
	#Create results and working directories
	if not os.path.exists('Results'):
		os.makedirs('Results')
	if not os.path.exists('Working'):
		os.makedirs('Working')
	
	#Make sure the vulnerability is valid
	if vulnerability != "":
		vulnCheck=0
		resultCount=0
		logsource=''
		print("Searching for evidence of \"" + vulnerability + "\"")
		print("  Host: " + sourceIP)
		
		try:
			configFile = 'config.xml'
			tree = ET.parse(configFile)
			root = tree.getroot()
		except:
			sys.exit("Not a valid config XML file")
		for settings in root.findall("./log_source"):
			logsource=settings.text
		cnx = getDBConnector()
		
		
		#check if vulnerability/asset combo exists in assetVulnerability Table
		cursor = cnx.cursor()
		query = ("SELECT count(*) as count from assetVulnerabilities where victim_ip = '" + str(ip2long(sourceIP)) + "' and threat_id = '" + vulnerability + "'")
		
		cursor.execute(query)
		for row in cursor:
			vulnCheck=row[0]
		cursor.close()
		
		if vulnCheck==0:
			#No combination exists, write data to DB
			
			cursor = cnx.cursor()
			add_vulnInstance = ("INSERT INTO assetVulnerabilities "
               "(victim_ip, threat_id, active) "
               "VALUES (%s, %s, %s)")
			vulnData = (ip2long(sourceIP), vulnerability, '1')
			
			# Insert new entry
			cursor.execute(add_vulnInstance , vulnData )
			
			cnx.commit()
			cursor.close()
			cnx.close()
		searchStringResults= findStixObservables.run(vulnerability)
		isExploitFound=False
		searchStringCount=0
		operator=searchStringResults[0]
		numResults=0
		if(searchStringResults[1]=="No search file found"):
			searchResults="0"
			print("  No search file found\n")
		elif(searchStringResults[1]=="No supported observables found"):
			searchResults="0"
			print("  No supported observables found\n")
		else:
			#run  search...
			#search should return number of results
			#Insert source host from arguments
			for entry in searchStringResults:
				if logsource=="splunk":
					if (searchStringCount == 1):
						searchString=entry + " AND (host=\"" + sourceHost + "\" OR s_ip=\"" + sourceIP + "\" OR d_host=\"" + sourceHost + "\")  | fields host, c_ip | fields - _bkt, _cd, _indextime, _kv, _serial, _si, _sourcetype | rename _raw as \"Raw Log\" | rename c_ip as clientip"
						numResults=splunk.searchVulnerability(searchString,vulnerability,sourceIP,sourceHost)
						if (numResults != "0"):
							data = json.load(numResults)
					
					if (operator=="AND"):
						if (searchStringCount > 1):
							resultCount=0
							for result in data["results"]:
								startTime =  dateutil.parser.parse(data["results"][resultCount]["_time"]) + datetime.timedelta(days =- 300)
								endTime =  dateutil.parser.parse(data["results"][resultCount]["_time"]) + datetime.timedelta(days = 300)
								searchString=entry + " AND (host=\"" + sourceHost + "\" OR s_ip=\"" + sourceIP + "\" OR d_host=\"" + sourceHost + "\") | fields host, clientip | fields - _bkt, _cd, _indextime, _kv, _serial, _si, _sourcetype | rename _raw as \"Raw Log\""
								newResults=splunk.searchVulnerabilityTimeRange(searchString,vulnerability,sourceIP,sourceHost,startTime.isoformat(),endTime.isoformat())
								if (newResults != "0"):
									#This is the result from search 1
									newData = json.load(newResults)
									newResultCount=0
									for result in newData["results"]:
										try:
											clientip=newData["results"][newResultCount]["clientip"]
										except:
											clientip="0"
										isExploitFound=True
										#These are the results from any further results proving the AND condition
										cnx = getDBConnector()
										cursor = cnx.cursor()
										query = ("SELECT count(*) as count from attackInventory where victim_ip = '" + str(ip2long(sourceIP)) + "' and threat_id = '" + vulnerability + "' and attack_time = '" + data["results"][resultCount]["_time"] + "'")
										cursor.execute(query)
										for row in cursor:
											logCheck=row[0]
										cursor.close()
										if logCheck==0:
											#Write data to DB
											cursor = cnx.cursor()
											add_logInstance = ("INSERT INTO attackInventory "
																"(victim_ip, attacker_ip, attack_time, attack_log, threat_id) "
																"VALUES (%s, %s, %s, %s, %s)")
											
											logData = (ip2long(sourceIP), ip2long(clientip), newData["results"][newResultCount]["_time"], newData["results"][newResultCount]["Raw Log"], vulnerability)
											# Insert new entry
											cursor.execute(add_logInstance , logData )
											cnx.commit()
											cursor.close()
										cnx.close()
										newResultCount=newResultCount+1
								else:
									newResultCount=0
							if (isExploitFound==True):
								try:
									clientip=data["results"][resultCount]["clientip"]
								except:
									clientip="0"
								cnx = getDBConnector()
								cursor = cnx.cursor()
								query = ("SELECT count(*) as count from attackInventory where victim_ip = '" + str(ip2long(sourceIP)) + "' and threat_id = '" + vulnerability + "' and attack_time = '" + data["results"][resultCount]["_time"] + "'")
								cursor.execute(query)
								for row in cursor:
									logCheck=row[0]
								cursor.close()
								if logCheck==0:
									#Write data to DB
									cursor = cnx.cursor()
									add_logInstance = ("INSERT INTO attackInventory "
														"(victim_ip, attacker_ip, attack_time, attack_log, threat_id) "
														"VALUES (%s, %s, %s, %s, %s)")
									
									logData = (ip2long(sourceIP), ip2long(clientip), data["results"][resultCount]["_time"], data["results"][resultCount]["Raw Log"], vulnerability)
									# Insert new entry
									cursor.execute(add_logInstance , logData )
									cnx.commit()
									cursor.close()
								cnx.close()
								resultCount=newResultCount+1
							else:
								resultCount=newResultCount
					elif (operator=="OR"):
						if (searchStringCount > 0):
							#only keep searching if there are more IOCS to look at...
							if len(searchStringResults)>2:
								searchString=entry + " AND (host=\"" + sourceHost + "\" OR s_ip=\"" + sourceIP + "\" OR d_host=\"" + sourceHost + "\")  | fields host, clientip | fields - _bkt, _cd, _indextime, _kv, _serial, _si, _sourcetype | rename _raw as \"Raw Log\""
								numResults=splunk.searchVulnerability(searchString,vulnerability,sourceIP,sourceHost)
								if (numResults != "0"):
									data = json.load(numResults)
									resultCount=0
									for result in data["results"]:
										isExploitFound=True
										cnx = getDBConnector()
										cursor = cnx.cursor()
										query = ("SELECT count(*) as count from attackInventory where victim_ip = '" + str(ip2long(sourceIP)) + "' and threat_id = '" + vulnerability + "' and attack_time = '" + data["results"][resultCount]["_time"] + "'")
										cursor.execute(query)
										for row in cursor:
											logCheck=row[0]
										cursor.close()
										if logCheck==0:
											#Write data to DB
											cursor = cnx.cursor()
											add_logInstance = ("INSERT INTO attackInventory "
																"(victim_ip, attacker_ip, attack_time, attack_log, threat_id) "
																"VALUES (%s, %s, %s, %s, %s)")
											logData = (ip2long(sourceIP), ip2long(data["results"][resultCount]["clientip"]), data["results"][resultCount]["_time"], data["results"][resultCount]["Raw Log"], vulnerability)
											
											# Insert new entry
											cursor.execute(add_logInstance , logData )
											
											cnx.commit()
											cursor.close()
										cnx.close()
										resultCount=resultCount+1
							elif len(searchStringResults)==2:
								searchString=entry + " AND (host=\"" + sourceHost + "\" OR host=\"" + sourceIP + "\" OR s_ip=\"" + sourceIP + "\" OR d_host=\"" + sourceHost + "\")  | fields host, clientip | fields - _bkt, _cd, _indextime, _kv, _serial, _si, _sourcetype | rename _raw as \"Raw Log\""
								numResults=splunk.searchVulnerability(searchString,vulnerability,sourceIP,sourceHost)
								if (numResults != "0"):
									data = json.load(numResults)
									resultCount=0
									for result in data["results"]:
										isExploitFound=True
										cnx = getDBConnector()
										cursor = cnx.cursor()
										query = ("SELECT count(*) as count from attackInventory where victim_ip = '" + str(ip2long(sourceIP)) + "' and threat_id = '" + vulnerability + "' and attack_time = '" + data["results"][resultCount]["_time"] + "'")
										cursor.execute(query)
										for row in cursor:
											logCheck=row[0]
										cursor.close()
										if logCheck==0:
											#Write data to DB
											cursor = cnx.cursor()
											add_logInstance = ("INSERT INTO attackInventory "
																"(victim_ip, attacker_ip, attack_time, attack_log, threat_id) "
																"VALUES (%s, %s, %s, %s, %s)")
											
											logData = (ip2long(sourceIP), ip2long(data["results"][resultCount]["clientip"]), data["results"][resultCount]["_time"], data["results"][resultCount]["Raw Log"], vulnerability)
											
											# Insert new entry
											cursor.execute(add_logInstance , logData )
											
											cnx.commit()
											cursor.close()
										cnx.close()
										resultCount=resultCount+1
					searchStringCount=searchStringCount+1
				elif logsource=="elastic_search":
					numResults=0
					startTime="-90d"
					endTime="now"
					#Insert source host from arguments
					entry = re.sub('\<source_host\>', sourceHost, entry)
					#Insert source IP from arguments
					entry = re.sub('\<source_ip\>', sourceIP, entry)
					if (searchStringCount == 1):
						#Insert startTime
						entry = re.sub('\<startTime\>', startTime, entry)
						#Insert endTime
						entry = re.sub('\<endTime\>', endTime, entry)
						if sourceIP == '*':
							entry = re.sub('\<min_count\>', '1', entry)
						else:
							entry = re.sub('\<min_count\>', '2', entry)
						#print entry
						searchResults = ElasticSearchQuery.searchVulnerability(entry,vulnerability,sourceIP,sourceHost)
						#print searchResults
						numResults = getElasticSearchResults(searchResults)
						#print numResults
					if (operator=="AND"):
						if (searchStringCount > 1):
							resultCount=0
							for hit in searchResults['hits']['hits']:
								startTime =  dateutil.parser.parse(hit["_source"]["@timestamp"]) + datetime.timedelta(days =- 1)
								
								endTime =  dateutil.parser.parse(hit["_source"]["@timestamp"]) + datetime.timedelta(days = 1)
								#Insert start time
								entry = re.sub('\<startTime\>', str(startTime.isoformat()), entry)
								#Insert end time
								entry = re.sub('\<endTime\>', str(endTime.isoformat()), entry)
								newSearchResults = ElasticSearchQuery.searchVulnerability(entry,vulnerability,sourceIP,sourceHost)
								newResults = getElasticSearchResults(newSearchResults)
								if (newResults != "0"):
									#This is the result from search 1
									newResultCount=0
									isExploitFound=True
									for newhit in newSearchResults['hits']['hits']:
										try:
											attackerIP=newhit["_source"]["evt_srcip"]
										except:
											attackerIP="0.0.0.0"
										#These are the results from any further results proving the AND condition
										cnx = getDBConnector()
										cursor = cnx.cursor()
										#Check original log hit
										query = ("SELECT count(*) as count from attackInventory where victim_ip = '" + str(ip2long(sourceIP)) + "' and threat_id = '" + vulnerability + "' and attack_log = '" + newhit["_source"]["message"] + "'")
										cursor.execute(query)
										for row in cursor:
											logCheck=row[0]
										cursor.close()
										if logCheck==0:
											#Write data to DB
											cursor = cnx.cursor()
											add_logInstance = ("INSERT INTO attackInventory "
																"(victim_ip, attacker_ip, attack_time, attack_log, threat_id) "
																"VALUES (%s, %s, %s, %s, %s)")
											
											logData = (ip2long(sourceIP), ip2long(attackerIP),hit["_source"]["@timestamp"], hit["_source"]["message"], vulnerability)
											# Insert new entry
											cursor.execute(add_logInstance , logData )
										cursor = cnx.cursor()
										#check new log hit
										query = ("SELECT count(*) as count from attackInventory where victim_ip = '" + str(ip2long(sourceIP)) + "' and threat_id = '" + vulnerability + "' and attack_log = '" + newhit["_source"]["message"] + "'")
										cursor.execute(query)
										for row in cursor:
											logCheck=row[0]
										cursor.close()
										if logCheck==0:
											#Write data to DB
											cursor = cnx.cursor()
											add_logInstance = ("INSERT INTO attackInventory "
																"(victim_ip, attacker_ip, attack_time, attack_log, threat_id) "
																"VALUES (%s, %s, %s, %s, %s)")
											
											logData = (ip2long(sourceIP), ip2long(attackerIP),newhit["_source"]["@timestamp"], newhit["_source"]["message"], vulnerability)
											# Insert new entry
											cursor.execute(add_logInstance , logData )
											
											cnx.commit()
											cursor.close()
										cnx.close()
										newResultCount=newResultCount+1
								else:
									newResultCount=0
								resultCount=newResultCount+1
								
								
								
					elif (operator=="OR"):
						if (searchStringCount == 1):
							if (int(numResults) > 0):
								resultCount = int(numResults)
								writeElasticSearchResults(searchResults,vulnObject,sourceIP,vulnerability)
								isExploitFound=True
						if (searchStringCount > 1):
							#Insert startTime
							entry = re.sub('\<startTime\>', startTime, entry)
							#Insert endTime
							entry = re.sub('\<endTime\>', endTime, entry)
							if sourceIP == '*':
								entry = re.sub('\<min_count\>', '1', entry)
							else:
								entry = re.sub('\<min_count\>', '2', entry)
							#only keep searching if there are more IOCS to look at...
							if len(searchStringResults)>1:
								searchResults = ElasticSearchQuery.searchVulnerability(entry,vulnerability,sourceIP,sourceHost)
								numResults = getElasticSearchResults(searchResults)
								if int(numResults) > 0:
									writeElasticSearchResults(searchResults,vulnObject,sourceIP,vulnerability)
								resultCount = resultCount + int(numResults)
					searchStringCount=searchStringCount+1
			if (isExploitFound==True):
				print("  Found " + str(resultCount) + " instances of exploitation!")
				print("  Generating attack logs") 
				#Parse through data list to get elastic timestamp for audit log times...
			else:
				print("  No instances of exploitation found.\n")
	else:
		resultCount=0
		print("Invalid vulnerability ID")
	return(resultCount)
