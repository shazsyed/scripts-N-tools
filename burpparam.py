import argparse
import re
import xml.etree.ElementTree as ET

from kiss_headers import parse_it

def main():
    parser = argparse.ArgumentParser(description="Parses Burp output XML files and extracts all parameters")
    parser.add_argument("-b", help="Burp output XML file", required=True, dest="xmlFile")
    parser.add_argument("-o", help="Text file output path", required=True, dest="destination")
    args = parser.parse_args()

    allParameters = parseXML(args.xmlFile)
    saveOutput(allParameters, args.destination)
    
def parseXML(XMLpath):
    allParameters = []

    tree = ET.parse(XMLpath)
    root = tree.getroot()

    for item in root.findall('item'):
        path = item.find('path').text
        request = item.find('request').text
        headers = parse_it(request)
        body = request.split('\n\n')[-1]

        allParameters.extend(getPathParameters(path))

        try:
           contentType = headers['Content-Type']

           if "application/json" in contentType:
               allParameters.extend(getJsonParameters(body))
           elif "application/x-www-form-urlencoded" in contentType:
               allParameters.extend(getFormParameters(body))
        except Exception as e:
            pass

    return allParameters

def saveOutput(allParameters, destination):
    allParameters = "\n".join(list(set(allParameters)))

    with open(destination, 'w') as file:
        file.write(allParameters)

def getPathParameters(path):
    pattern = r"[\&\?](.*?)\="
    parameters = re.findall(pattern, path)
    return parameters

def getJsonParameters(body):
    pattern = r"[{,]\"(\w*?)\":"
    parameters = re.findall(pattern, body)
    return parameters


def getFormParameters(body):
    pattern = r"(?:\A|\&)(.*?)\="
    parameters = re.findall(pattern, body)
    return parameters

if __name__ == '__main__':
    main()
