

#1-attribute present (phishing)
#0-suspecious
#-1-attribute absent( legitimate)

# 5/30.............................status
import requests
from bs4 import BeautifulSoup
'''
import requests 


url='https://httpbin.org/get'

PARAMS = {'domains': (url,)} 
HEADERS = {'API-OPR':'o084koosw8k44sgg4k0gsswocgwowogk440cc040'}

r = requests.get('https://openpagerank.com/api/v1.0/getPageRank', headers=HEADERS, params=PARAMS)

print r.text

'''
url='https://www.ktustudy.in/computer-science-s8-syllabus'


labels=[0]*30
#1.having IP address
url_tokens='/'.join(url.split('//')).split('/')
print url_tokens
domain=url_tokens[1]
having_IP=0

#2.URL length
length=len(url)
if length <54:
    url_len=-1
elif length>=54 and length<75:
    url_len=0
else:
    url_len=1
#3.URL shortening services
shortining=0
#4.URL is having ar symbol
if '@' in url:
    having_at=1
else:
    having_at=-1
#5.redirecting using //
position= url.rfind("//")
print position
if(position<7):
    doubleSlash_redirecting=-1
else:
    doubleSlash_redirecting=1

#6.Adding Prefix or Suffix Separated by (-) to the Domain
if '-' in url_tokens[1]:
    prefix_suffix=1
else:
    prefix_suffix=-1
#7.Sub Domain and Multi Sub Domains
having_Sub_Domain=0
#8.HTTPS (Hyper Text Transfer Protocol with Secure Sockets Layer)
if(url_tokens[0]=='https:'):
    sSLfinal_State=-1
else:
    sSLfinal_State=1 

#9.Domain Registration Length
Domain_registeration_length=0
#10.Favicon
Favicon=0
#11.Using Non-Standard Port
port=0
#12.The Existence of HTTPs Token in the Domain Part of the URL
HTTPS_token=0
#13.Request URL
Request_URL=0
#14.URL of Anchor
URL_of_Anchor=0
#15.Links in <Meta>, <Script> and <Link> tags
Links_in_tags=0
#16.Server Form Handler (SFH)
SFH=0
#17.Submitting Information to Email
Submitting_to_email=0
#18.Abnormal URL
Abnormal_URL=0
#19.Website Forwarding
Redirect=0
# 20.Status Bar Customization
on_mouseover=0
# 21.Disabling Right Click
RightClick=0
# 22.Using Pop-up Window
popUpWidnow=0

# 23.IFrame Redirection
Iframe=0
# 24.Age of Domain
age_of_domain=0
# 25.DNS Record
DNSRecord=0
# 26.Website Traffic
web_traffic=0
# 27.PageRank
Page_Rank=0
# 28.Google Index
google_index=0
# 29.Number of Links Pointing to Page
Links_pointing_to_page=0
# 30.Statistical-Reports Based Feature
Statistical_report=0


labels=[having_IP,url_len,shortining,having_at,doubleSlash_redirecting,prefix_suffix,having_Sub_Domain,sSLfinal_State,Domain_registeration_length,Favicon,port,HTTPS_token,Request_URL,URL_of_Anchor,Links_in_tags,SFH,Submitting_to_email,Abnormal_URL,Redirect,on_mouseover,RightClick,popUpWidnow,Iframe,age_of_domain,DNSRecord,web_traffic,Page_Rank,google_index,Links_pointing_to_page,Statistical_report]
print labels
