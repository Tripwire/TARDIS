try:
	import subprocess
except ImportError:
	print "No subprocess!"
try:
	import json
except ImportError:
	print "No json!"
try:
	import os
except ImportError:
	print "No os!"
try:
	import re
except ImportError:
	print "No re!"
try:
	import sys
except ImportError:
	print "No sys!"
try:
	import datetime
except ImportError:
	print "No datetime!"
try:
	import socket
except ImportError:
	print "No socket!"
try:
	import struct
except ImportError:
	print "No struct!"
try:
	import urllib2
except ImportError:
	print "No urllib2!"
try:
	import pxssh
except ImportError:
	print "No pexpext/pxssh, try pip install pexpect"
try:
	import csv
except ImportError:
	print "No csv!"
try:
	import shutil
except ImportError:
	print "No shutil!"
try:
	import argparse
except ImportError:
	print "No argparse, try pip install argparse"
try:
	import base64
except ImportError:
	print "No base64!"
try:
	import cookielib
except ImportError:
	print "No cookielib!"
try:
	import email
except ImportError:
	print "No email!"
try:
	import requests
except ImportError:
	print "No requests, try pip install requests"
try:
	import xml.etree.ElementTree as ET
except ImportError:
	print "No xml etree!"
try:
	from collections import defaultdict
except ImportError:
	print "No collections defaultdict!"
try:
	import dateutil.parser
except ImportError:
	print "No dateutil parser, try pip install python-dateutil"
try:
	import mysql.connector
except ImportError:
	print "No mysql connector, try pip install --allow-external mysql-connector-python mysql-connector-python"
try:
	from elasticsearch import Elasticsearch
except ImportError:
	print "No elasticsearch, try pip install elasticsearch"
try:
	import splunklib.client as client
except ImportError:
	print "No splunk, try pip install splunk-sdk"
try:
	from stix.core import STIXPackage
except ImportError:
	print "No STIX, try pip intsall stix"
try:
	from cybox.objects.win_event_log_object import WinEventLog
except ImportError:
	print "No TAXI, try pip intsall stix"

