#!/usr/bin/python
# Virus Total API Integration Script
# Built on VT Test Script from: Adam Meyers ~ CrowdStrike
# Rewirtten / Modified / Personalized: Chris Clark ~ GD Fidelis CyberSecurity
# If things are broken let me know chris@xenosec.org
# No Licence or warranty expressed or implied, use however you wish! 

import json, urllib, urllib2, argparse, hashlib, re, sys
from pprint import pprint
import win32gui

class vtAPI():
    def __init__(self):
        self.api = 'd2ad311bb6034c64509c3c10ec39f85dc508c3d5a219d72ad1c1d003a4553283'
        self.base = 'https://www.virustotal.com/vtapi/v2/'
    
    def getReport(self,md5):
        param = {'resource':md5,'apikey':self.api,'allinfo': '1'}
        url = self.base + "file/report"
        data = urllib.urlencode(param)
        result = urllib2.urlopen(url,data)
        jdata =  json.loads(result.read())
        return jdata



# Md5 Function

def checkMD5(checkval):
  if re.match(r"([a-fA-F\d]{32})", checkval) == None:
    md5 = md5sum(checkval)
    return md5.upper()
  else: 
    return checkval.upper()

def md5sum(filename):
  fh = open(filename, 'rb')
  m = hashlib.md5()
  while True:
      data = fh.read(8192)
      if not data:
          break
      m.update(data)
  return m.hexdigest() 
          
def parse(it, md5, verbose, jsondump):
  if it['response_code'] == 0:
    print md5 + " -- Not Found in VT"
    return 0
  f=open("C:\Users\Administrator\Desktop\ScanHistory.txt",'a+')
  f.write(str(sys.argv))
  f.write("\nResults for MD5: "+it['md5'])
  f.write("\nDetected by: "+str(it['positives'])+"/"+str(it['total']))
  if verbose == True:
	f.write('\n\tVerbose VirusTotal Information Output:\n')	
	for x in it['scans']:
		if len(x) <=7:
			f.write('\t'+ x+'\t' +'\t'+'\t'+str(it['scans'][x]['result'])+'\n')
		else:
			f.write('\t'+ x+'\t' +'\t'+str(it['scans'][x]['result'])+'\n')
  elif verbose==False:
	  f.write('\n\tKaspersky Detection:'+str(it['scans']['Kaspersky']['result']))
	  f.write('\n\tTrendMicro Detection:'+str(it['scans']['TrendMicro']['result'])) 
	  f.write('\n\tAVG Detection:'+str(it['scans']['AVG']['result']))
	  f.write('\n\tClamAV Detection:'+str(it['scans']['ClamAV']['result']))
	  f.write('\n\tTheHacker Detection:'+str(it['scans']['TheHacker']['result']))
	  f.write('\n\tCMC Detection:'+str(it['scans']['CMC']['result']))
	  f.write('\n\tAvast Detection:'+str(it['scans']['Avast']['result']))
	  f.write('\n\tBkav Detection:'+str(it['scans']['Bkav']['result']))
	  f.write('\n\tKingsoft Detection:'+str(it['scans']['Kingsoft']['result']))
	  f.write('\n\tMicrosoft Detection:'+str(it['scans']['Microsoft']['result']))
	  print'\nOverview VirusTotal Information Output:\n'
	  print'\n\tKaspersky Detection:'+str(it['scans']['Kaspersky']['result'])
	  print'\n\tTrendMicro Detection:'+str(it['scans']['TrendMicro']['result'])
	  print'\n\tAVG Detection:'+str(it['scans']['AVG']['result'])
	  print'\n\tClamAV Detection:'+str(it['scans']['ClamAV']['result'])
	  print'\n\tTheHacker Detection:'+str(it['scans']['TheHacker']['result'])
	  print'\n\tCMC Detection:'+str(it['scans']['CMC']['result'])
	  print'\n\tAvast Detection:'+str(it['scans']['Avast']['result'])
	  print'\n\tBkav Detection:'+str(it['scans']['Bkav']['result'])
	  print'\n\tKingsoft Detection:'+str(it['scans']['Kingsoft']['result'])
	  print'\n\tMicrosoft Detection:'+str(it['scans']['Microsoft']['result'])
	  print'\nScanned on:'+it['scan_date']
	  print'\n-----------------code socket by faraanh96---------------------\n\n'
  f.write('\nScanned on:'+it['scan_date'])
  f.write('\n-----------------code socket by faraanh96---------------------\n\n')
  f.close()
  if verbose == True:
    print '\n\tVerbose VirusTotal Information Output:\n'
    for x in it['scans']:
     print '\t', x,'\t' if len(x) < 7 else '','\t' if len(x) < 14 else '','\t',it['scans'][x]['detected'], '\t',it['scans'][x]['result']
  print '\nScan History is stored in ScanHistory.txt on your desktop'

def main():
	#hwnd = win32gui.GetForegroundWindow()
	#win32gui.SetWindowPos(hwnd,0, 0, 1000, 0, 0, 0)
	print"""
@@@@@          @@@              ***
@@@@@@@        @@@             *****	
@@@   @@@      @@@           ***    ***
@@@    @@@     @@@          ***      ***
@@@     @@@    @@@         ***        ***
@@@      @@@   @@@        ***==========***
@@@       @@@  @@@       ***            ***
@@@        @@@ @@@      ***              ***
@@@         @@@@@@     ***                ***
@@@__________@@@@@____***__________________***_______________
Scan for malware program using API of Virus Total________
Coded by faraanh96@gmail.com_________________________
Powered by Python27______________________________
													 """
	opt=argparse.ArgumentParser(description="Search from VirusTotal")
	opt.add_argument("HashorPath", help="Enter the MD5 Hash or Path to File")
	opt.add_argument("-s", "--search", action="store_true", help="Search VirusTotal")
	opt.add_argument("-v", "--verbose", action="store_true", dest="verbose", help="Turn on verbosity of VT reports")
	opt.add_argument("-j", "--jsondump", action="store_true",help="Dumps the full VT report to file (VTDLXXX.json)")

	if len(sys.argv)<=2:
		opt.print_help()
		sys.exit(1)
	options= opt.parse_args()
	vt=vtAPI()
	md5 = checkMD5(options.HashorPath)
	if options.search or options.jsondump or options.verbose:
		parse(vt.getReport(md5), md5 ,options.verbose, options.jsondump)


if __name__ == '__main__':
    main()
