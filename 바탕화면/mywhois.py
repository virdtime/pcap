import pythonwhois
import sys

if len(sys.argv)==1:
	print "Usage: [python] [mywhois.py] [option] [domain/file path]"
	print "option: -d, domain, -f openfile"
	print "we are only print Host Name!!"
	sys.exit(1)

if sys.argv[1]=="-d":
	l=pythonwhois.net.get_whois_raw(sys.argv[2],with_server_list=False)
	if l[0].find("DNSSEC")!=-1 : sys.exit()
	t=l[0].find("Host")
	c=0
	for i in range(t,len(l[0])): 
		if l[0][i]=='\n': 
			break
		c+=1
	host=l[0][t:t+c].split()
	host=host[3]
	t=l[0].find("IPv4") 
	c=0
	for i in range(t,len(l[0])): 
		if l[0][i]=='\n': 
			break
		c+=1
	IPv4=l[0][t:t+c].split()
	IPv4=IPv4[2]
	t=l[0].find("Registered")
	c=0
	for i in range(t,len(l[0])): 
		if l[0][i]=='\n': 
			break
		c+=1
	Reg=l[0][t:t+c].split()
	Reg=Reg[3]+Reg[4]+Reg[5]
	t=l[0].find("Last")
	c=0
	for i in range(t,len(l[0])): 
		if l[0][i]=='\n': 
			break
		c+=1
	Last=l[0][t:t+c].split()
	Last=Last[4]+Last[5]+Last[6]
	t=l[0].find("AC E")
	c=0
	for i in range(t,len(l[0])): 
		if l[0][i]=='\n': 
			break
		c+=1
	Ema=l[0][t:t+c].split()
	Ema=Ema[3]
	t=l[0].find("AC P")
	c=0
	for i in range(t,len(l[0])): 
		if l[0][i]=='\n': 
			break
		c+=1
	phone=l[0][t:t+c].split()
	phone=phone[4]
	t=l[0].find("Authorized")
	c=0
	for i in range(t,len(l[0])): 
		if l[0][i]=='\n': 
			break
		c+=1
	Auth=l[0][t:t+c].split()
	Auth=Auth[3]+Auth[4]
	print "{\"Host\":"+host+", \"IPv4\":"+IPv4+", \"Registered Date\":"+Reg+", \"Last updated date\":"+Last+", \"Email\":"+Ema+", \"Phone number\":"+phone+", \"Authorized Agency\": "+Auth+"}"

if sys.argv[1]=="-f":
	f=open(sys.argv[2],"r")
	while True:
		line=f.readline()
		if not line: break
		l=pythonwhois.net.get_whois_raw(line,with_server_list=False)
		if l[0].find("DNSSEC")!=-1 : break
		t=l[0].find("Host")
		c=0
		for i in range(t,len(l[0])): 
			if l[0][i]=='\n': 
				break
			c+=1
		host=l[0][t:t+c].split()
		host=host[3]
		t=l[0].find("IPv4") 
		c=0
		for i in range(t,len(l[0])): 
			if l[0][i]=='\n': 
				break
			c+=1
		IPv4=l[0][t:t+c].split()
		IPv4=IPv4[2]
		t=l[0].find("Registered")
		c=0
		for i in range(t,len(l[0])): 
			if l[0][i]=='\n': 
				break
			c+=1
		Reg=l[0][t:t+c].split()
		Reg=Reg[3]+Reg[4]+Reg[5]
		t=l[0].find("Last")
		c=0
		for i in range(t,len(l[0])): 
			if l[0][i]=='\n': 
				break
			c+=1
		Last=l[0][t:t+c].split()
		Last=Last[4]+Last[5]+Last[6]
		t=l[0].find("AC E")
		c=0
		for i in range(t,len(l[0])): 
			if l[0][i]=='\n': 
				break
			c+=1
		Ema=l[0][t:t+c].split()
		Ema=Ema[3]
		t=l[0].find("AC P")
		c=0
		for i in range(t,len(l[0])): 
			if l[0][i]=='\n': 
				break
			c+=1
		phone=l[0][t:t+c].split()
		phone=phone[4]
		t=l[0].find("Authorized")
		c=0
		for i in range(t,len(l[0])): 
			if l[0][i]=='\n': 
				break
			c+=1
		Auth=l[0][t:t+c].split()
		Auth=Auth[3]+Auth[4]
		tmp="{\"Host\":"+host+", \"IPv4\":"+IPv4+", \"Registered Date\":"+Reg+", \"Last updated date\":"+Last+", \"Email\":"+Ema+", \"Phone number\":"+phone+", \"Authorized Agency\": "+Auth+"}"
		fi=open("Parser Whois.txt","a+")
		fi.write(tmp)
		fi.close()
	f.close()

	
