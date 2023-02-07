from flask import Flask, render_template, url_for, request
import pickle
import numpy as np
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from googlesearch import search
import requests
import whois
from datetime import date
import urllib.request
import ipaddress
import re
import socket
import dns.resolver

app = Flask(__name__)

#Load the pickle model
model = pickle.load(open("C:\\Users\\User10\\Documents\\VisualStudio\\phishingURLchecker_FYP\\model.pkl", "rb"))


@app.route("/", methods=['GET'])
def home():
    return render_template("index.html")

#Function of url features
def https(url):
    try:
        Https = urlparse(url).scheme
        if 'https' in Https:
            return -1
        else:
            return 1
    except:
        return 1

def AnchorURL(url):
    url = requests.get(url)
    soup = BeautifulSoup(url.text, 'html.parser')
    try:
        i,unsafe = 0,0
        for a in soup.find_all('a', href=True):
            if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (url in a['href'] or urlparse(url).netloc in a['href']):
                unsafe = unsafe + 1
            i = i + 1
        try:
            percentage = unsafe / float(i) * 100
            if percentage < 33.0:
                return -1
            elif ((percentage >= 33.0) and (percentage < 67.0)):
                return 0
            else:
                return 1
        except:
            return 0
    except:
        return 1

def prefixSuffix(url):
    try:
        if re.findall('\-',urlparse(url).netloc):
            return 1
        return -1
    except:
        return 1

def WebsiteTraffic(url):
    try:
        rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find("REACH")['RANK']
        if (int(rank) < 100000):
            return -1
        else:
            return 1
    except :
        return -1

def subDomains(url):
    dot = len(re.findall("\.", url))
    if dot == 1:
        return -1
    elif dot == 2:
        return 0
    return 1

def requestURL(url):
    url = requests.get(url)
    soup = BeautifulSoup(url.text, 'html.parser')
    try:
        for img in soup.find_all('img', src=True):
            dots = [x.start(0) for x in re.finditer('\.', img['src'])]
            if url in img['src'] or urlparse(url).netloc in img['src'] or len(dots) == 1:
                success = success + 1
            i = i+1

        for audio in soup.find_all('audio', src=True):
            dots = [x.start(0) for x in re.finditer('\.', audio['src'])]
            if url in audio['src'] or urlparse(url).netloc in audio['src'] or len(dots) == 1:
                success = success + 1
            i = i+1

        for embed in soup.find_all('embed', src=True):
            dots = [x.start(0) for x in re.finditer('\.', embed['src'])]
            if url in embed['src'] or urlparse(url).netloc in embed['src'] or len(dots) == 1:
                success = success + 1
            i = i+1

        for iframe in soup.find_all('iframe', src=True):
            dots = [x.start(0) for x in re.finditer('\.', iframe['src'])]
            if url in iframe['src'] or urlparse(url).netloc in iframe['src'] or len(dots) == 1:
                success = success + 1
            i = i+1

        try:
            percentage = success/float(i) * 100
            if percentage < 33.0:
                return -1
            elif((percentage >= 33.0) and (percentage < 67.0)):
                return 0
            else:
                return 1
        except:
            return 0
    except:
        return 1

def LinksInScriptTags(url):
    url = requests.get(url)
    soup = BeautifulSoup(url.text, 'html.parser')
    try:
        i,success = 0,0        
        for link in soup.find_all('link', href=True):
            dots = [x.start(0) for x in re.finditer('\.', link['href'])]
            if url in link['href'] or urlparse(url).netloc in link['href'] or len(dots) == 1:
                success = success + 1
            i = i+1

        for script in soup.find_all('script', src=True):
            dots = [x.start(0) for x in re.finditer('\.', script['src'])]
            if url in script['src'] or urlparse(url).netloc in script['src'] or len(dots) == 1:
                success = success + 1
            i = i+1

        try:
            percentage = success / float(i) * 100
            if percentage < 33.0:
                return -1
            elif((percentage >= 33.0) and (percentage < 67.0)):
                return 0
            else:
                return 1
        except:
            return 0
    except:
        return 1

def ServerFormHandler(url):
    url = requests.get(url)
    soup = BeautifulSoup(url.text, 'html.parser')
    try:
        if len(soup.find_all('form', action=True))==0:
            return 1
        else :
            for form in soup.find_all('form', action=True):
                if form['action'] == "" or form['action'] == "about:blank":
                    return 1
                elif url not in form['action'] and urlparse(url).netloc not in form['action']:
                    return 0
                else:
                    return -1
    except:
        return 1

def GoogleIndex(url):
    try:
        site = search(url,5)
        if site:
            return -1
        else:
            return 1
    except:
        return -1

def AgeofDomain(url):
    try:
        url = whois(urlparse(url).netloc)
        try:
            creation_date = url
            try:
                if(len(creation_date)):
                    creation_date = creation_date[0]
            except:
                pass

            today  = date.today()
            age = (today.year-creation_date.year)*12+(today.month-creation_date.month)
            if age >=6:
                return -1
            else:
                return 1
        except:
            return -1
    except:
        return -1

def PageRank(url):
    try:
        rank_checker_response = requests.post("https://www.checkpagerank.net/index.php", {"name": urlparse(url).netloc})
        global_rank = int(re.findall(r"Global Rank: ([0-9]+)", rank_checker_response.text)[0])
        if global_rank > 0 and global_rank < 100000:
            return -1
        else:
            return 1
    except:
        return 1

def havingIP(url):
    try:
        if ipaddress.ip_address(url):
            return 1
        else:
            return -1
    except:
        return 1

def StatsReport(url):
    try:
        url_match = re.search(
        'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', url)
        ip_address = socket.gethostbyname(urlparse(url).netloc)
        ip_match = re.search('146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
                                '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
                                '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
                                '216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
                                '34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
                                '216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42', ip_address)
        if url_match:
            return 1
        elif ip_match:
            return 1
        return -1
    except:
        return -1

def DNSRecord(url):
    try:
        domain = url
        answer = dns.resolver.resolve(domain, 'NS')
        if answer:
            return -1
        return 1
    except:
        return 1

def URLength(url):
    if len(url) < 54:
        return -1
    elif len(url) >= 54 and len(url) <= 75:
        return 0
    else:
        return 1

def havingAtSymbol(url):
    try:
        if re.findall('@',url):
            return 1
        else:
            return -1
    except:
        return 1

def mouseOver(url):
    url = requests.get(url)
    try:
        if re.findall("<script>.+onmouseover.+</script>", url.text):
            return 1
        else:
            return -1
    except:
        return 1

def Port(url):
    try:
        port = urlparse(url).netloc.split(":")
        if len(port)>1:
            return 1
        else:
            return -1
    except:
        return 1

def LinksPointingToPage(url):
    url = requests.get(url)
    try:
        number_of_links = len(re.findall(r"<a href=", url.text))
        if number_of_links == 0:
            return 1
        elif number_of_links <= 2:
            return 0
        else:
            return -1
    except:
        return -1

@app.route("/predict", methods=["GET", "POST"])
def predict():
    message=''
    try:
        if request.method == 'POST':
            url =  request.form['url']
            features = np.array([https(url),AnchorURL(url),prefixSuffix(url),WebsiteTraffic(url),subDomains(url),requestURL(url),LinksInScriptTags(url),ServerFormHandler(url),GoogleIndex(url),AgeofDomain(url),PageRank(url),havingIP(url),StatsReport(url),DNSRecord(url),URLength(url),havingAtSymbol(url),mouseOver(url),Port(url),LinksPointingToPage(url)])
            final_features = features.reshape(-1, 19)
            prediction  = model.predict(final_features)
            return render_template("index.html", message=url, prediction_text=prediction)
        else:
            return render_template("index.html", prediction_text="Something went wrong")
    except BaseException:
        prediction=1 
        return render_template("index.html", message=url, prediction_text=prediction)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8000, debug=True)