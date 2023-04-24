#Imported Library's

import pandas as pd
import json
import os
import glob
import openpyxl
from datetime import datetime

# Getting the directory path

path1 = os.getcwd()

#Adding the folder with the JSON files
path2 = path1 + "\\20230407trivy"

#collecting the json file names into a single variable for recall.
json_files = glob.glob(os.path.join(path2, "*.json"))

#Getting the information from the JSON files into a variable as raw data
containersInfo = {}
#List of all containers == first level key for containersInfo dict
containerList = []

for files in json_files:
    f = open(files, encoding='utf8')
    container = files.split("\\")[-1].split(".")[0]
    
    try:

        test_json = json.load(f)
        containerList.append(container)
        containersInfo.update({container: test_json})
        f.close()
    except:
        f.close()
        pass

#Configuring the data format, and selecting the columns to process

rk_sys_vulns = {}
#Master list
columns = ['Container', 'OS', 'Class', 'Type', 'VulnerabilityID', 'PkgName', 'InstalledVersion', 'FixedVersion', 'Title', 'Description', 'Severity', 'CWEID', 'PublishedDate', 'LastModifiedDate']

for column in columns:
    rk_sys_vulns[column] = []

#Set of columns within the Vulnerability list for cycling through later
columns2 =['VulnerabilityID', 'PkgName', 'InstalledVersion', 'FixedVersion', 'Title', 'Description', 'Severity', 'CWEID', 'PublishedDate', 'LastModifiedDate']

#Formatting the raw data into a format for data frames
finalizedData = {}


count = 0
#Breaks out the data stored for each individual container
for container in containersInfo:
   #Used try to catch empty data sets
    try:
        #Cycles through the different results
        for result in containersInfo[container]['Results']:
                      
            try:
                #Cycles through each finding for each of the classes and type
                for vulns in result['Vulnerabilities']:
                        
                    #this addes in the first several columns from the base container and the pkg class and type to be added with the finding
                    try:
                        #This is the new code to identify the containers base image
                        osFamily = containersInfo[container]['Metadata']['OS']['Family'] +' ' + containersInfo[container]['Metadata']['OS']['Name']
                        
                        data = []
                        data = [['Container', container], ['OS', osFamily ], ['Class', result['Class']], ['Type', result['Type']]]
                    except:
                        data = []
                        data = [['Container', container], ['OS', ' ' ], ['Class', result['Class']], ['Type', result['Type']]]
                        

                    for c in columns2:
                        #This adds the information for each finding in with the base data that was added above.

                        try:
                            data = data + [[c, vulns[c]]]
                        except:
                            data = data + [[c, '']]
                                

                    #This creates a row of data into the data set to later be converted into a dataframe.
                    finalizedData[count] = data
                    count = count + 1
                        
            except:
                pass
            

    except:
        pass

#Creates the empty dataframe
data = pd.DataFrame()

#Takes the collected data from above and sets it for reading in the dataframe.
for entry in finalizedData:
    for item in finalizedData[entry]:
        rk_sys_vulns[item[0]].append(item[1])

data=pd.DataFrame(rk_sys_vulns)

pathDate = datetime.today().strftime('%Y%m%d')

#Sets the file name when saving the excel file.
path3 = path1 + "\latest_" + pathDate + ".xlsx"

#Writing file to excel
with pd.ExcelWriter(path3) as writer:
    #creating loop for cycling through list of files and adding them sheet by sheet to the excel object.
    data.to_excel(writer, sheet_name= 'Results', index=False)


