import datetime, re, os
# Making my own version of fastrack.txt, just cause I guess.
commonWords=[
"winter",
"summer",
"autumn",
"fall",
"spring",
"dog",
"god",
"jesus",
"business",
"password",
"root",
"toor",
"supertux",
"admin",
"administrator",
"boss",
"owner",
"cloud",
"management",
"user",
"support"
]


def UpperCaseLettersOneByOne(word):
		for c in range(0,len(word)):
			modifiedWord=word[:c]+word[c].upper()+word[c+1:]
			writeToFile(modifiedWord)

def addNumbersTwoDigit(word):
		year=int(datetime.date.today().strftime("%y"))
		startyear=year-5
		endyear=year+5
		for i in range(startyear,endyear):
			modifiedWord=word+str(f"{i:0{2}}")
			writeToFile(modifiedWord)
		for i in range(startyear,endyear):
			modifiedWord=str(f"{i:0{2}}")+word
			writeToFile(modifiedWord)

def addNumbersFourDigit(word):
		year=datetime.date.today().year
		startyear=year-5
		endyear=year+5
		for i in range(startyear,endyear):
			modifiedWord=word+str(f"{i:0{4}}")
			writeToFile(modifiedWord)
		for i in range(startyear,endyear):
			modifiedWord=str(f"{i:0{4}}")+word
			writeToFile(modifiedWord)

def addSpecialChars(word):
		for each in ["!", "@", "#","$","%","^","&","*","_","-","+","=","?",",",".",":",";"]:
			newword1=str(each)+word
			newword2=word+str(each)
			writeToFile(newword1)
			writeToFile(newword2)

def substitutions(word):
	if "e" in word:
		new1=word.replace('e',"3")
		writeToFile(new1)
	if "a" in word:
		new2=word.replace("a","4")
		writeToFile(new2)
	if "i" in word:
		new3=word.replace("i","!")
		writeToFile(new3)
	if "o" in word:
		new4=word.replace("o","0")
		writeToFile(new4)
	replacements = [("e", "3"), ("a", "4"), ("i", "!"),("o","0")]
	for old, new in replacements:
		combinedWord=word.replace(old,new)
	writeToFile(combinedWord)


def runAllOnceWithoutTree(word):
	if not bool(re.search(r'\d', word)):
		addNumbersFourDigit(word)
		addNumbersTwoDigit(word)
	if not bool(re.search(r'[\!\@\#\$\%\^\&\*\+\=\_\-\?\,\.\:\;]', word)):
		addSpecialChars(word)
	if not bool(re.search(r'[A-Z]', word)):
		UpperCaseLettersOneByOne(word)
	if not bool(re.fullmatch(r'[A-Za-z0-9@#$%^&+=]{10,}', word)):
		substitutions(word)

def writeToFile(word):
	open('fastrack.txt-tmp', 'a').write(word+"\n")


for each in commonWords:
		writeToFile(each)
		runAllOnceWithoutTree(each)
with open('fastrack.txt-tmp','r') as file:
	for each in file.readlines():
		runAllOnceWithoutTree(each.replace('\n',''))
# second run just to ensure nothing gets missed :D
with open('fastrack.txt-tmp','r') as file:
	for each in file.readlines():
		runAllOnceWithoutTree(each.replace('\n',''))
# Cleanup Duplicates
seen_lines = set()
with open("fastrack.txt-tmp", 'r') as infile, open("fastrack.txt", 'w') as outfile:
	for line in infile:
		if line not in seen_lines:
			seen_lines.add(line)
			outfile.write(line)
os.remove("fastrack.txt-tmp")