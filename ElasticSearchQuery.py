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


from datetime import datetime
from elasticsearch import Elasticsearch
import xml.etree.ElementTree as ET
import socket, struct
import mysql.connector

def ip2long(ip):
	return struct.unpack("!L", socket.inet_aton(ip))[0]


def searchVulnerability(searchString,vulnerability,sourceIP,sourceHost):
	#Get Settings
	elasticSearch_ip=''
	db_ip=''
	db_user=''
	db_name=''
	db_pass=''
	try:
		configFile = 'config.xml'
		tree = ET.parse(configFile)
		root = tree.getroot()
	except:
		sys.exit("Not a valid XML file")
	for settings in root.findall("./elastic_search"):
		for ip in settings.findall("./ip"):
			elasticSearch_ip=ip.text
	for dbsettings in root.findall("./db"):
		for dbip in dbsettings.findall("./ip"):
			db_ip=dbip.text
		for dbname in dbsettings.findall("./db_name"):
			db_name=dbname.text
		for dbuser in dbsettings.findall("./user"):
			db_user=dbuser.text
		for dbpass in dbsettings.findall("./password"):
			db_pass=dbpass.text
	
	es = Elasticsearch(
	[
		#Example: 'http://192.168.1.12:9200/',
		elasticSearch_ip,

	]
	)
	
	
	res = es.search(index="logstash-*", body=searchString)
	
	return(res)
