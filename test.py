from oauth2 import OAuth2

import webbrowser
import requests
import json

client_id = ''
client_secret=''

oauth2_handler = OAuth2(client_id, client_secret, "https://api.weibo.com/", 
		"http://stephenlee.github.com", "oauth2/authorize", "oauth2/access_token")

authorization_url = oauth2_handler.authorize_url()
webbrowser.open(authorization_url)
code = raw_input('please input the code ')
response = oauth2_handler.get_token(code)

oauth2_client = requests.session(params={'access_token': response['access_token']})

#r = oauth2_client.get('https://api.weibo.com/2/statuses/public_timeline.json')
#r = oauth2_client.get('https://api.weibo.com/2/statuses/friends_timeline.json')


def get_onepage_user_weibo(uid, count=100, page=1):
    r=oauth2_client.get("https://api.weibo.com/2/statuses/user_timeline.json?uid=%s&count=%s&page=%s" % (uid,count,page))
    print r.status_code
    tweets=json.loads(r.text)
    f=open('%s.txt' % uid,'a')
    for status in tweets[u'statuses']:
        status_text=status[u'text']
        f.write("%s\n" % status_text.encode('utf-8'))
	f.close()

def get_user_weibo(uid, count,pages):
     for page in range(1,pages+1):
         get_onepage_user_weibo(uid, count, page)

def main():
    #likaifu 5000 tweets
    #get_user_weibo(1197161814,100,50)
    #yangmi 2000 tweets
    #get_user_weibo(1195242865,100,20)
    #renzhiqiang 10000 tweets
    #get_user_weibo(1182389073,100,100)


if __name__ == "__main__":
    main()





