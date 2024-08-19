from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.chrome.options import Options
import time
import requests
import base64
from threading import Thread
from datetime import datetime
from urllib.parse import urlencode



##############################
#Spotify App credentials here:
clientID = ''
clientSecret = ''
#Instagram credentials here:
instagramUsername = '' #or E-Mail
instagramPassword = ''
#Spotify credentials here:
spotifyUsername = '' #or E-Mail
spotifyPassword = ''
##############################



driverGlobal = webdriver.Chrome()
authCode = ''
accessToken = ''
refreshToken = ''


def authorizeApp():

    #documentation:
    #https://developer.spotify.com/documentation/web-api/tutorials/code-flow

    auth_headers = {
    "client_id": clientID,
    "response_type": "code",
    "redirect_uri": "http://localhost:8888/callback",
    "scope": "user-read-currently-playing"
    }
    
    driverGlobal.get("https://accounts.spotify.com/authorize?" + urlencode(auth_headers))
    username = driverGlobal.find_element(By.ID, "login-username").send_keys(spotifyUsername)
    password = driverGlobal.find_element(By.ID, "login-password").send_keys(spotifyPassword)
    btnLogin = WebDriverWait(driverGlobal, 10).until(EC.element_to_be_clickable((By.ID, "login-button"))).click()
    time.sleep(10)

    url = driverGlobal.current_url
    code = url.split('=')
    global authCode
    authCode = code[1]
   

def getAuthToken():

    encoded_credentials = base64.b64encode(clientID.encode() + b':' + clientSecret.encode()).decode("utf-8")

    token_headers = {
        "Authorization": "Basic " + encoded_credentials,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    token_data = {
        "grant_type": "authorization_code", 
        "code": authCode,
        "redirect_uri": "http://localhost:8888/callback"
    }

    r = requests.post("https://accounts.spotify.com/api/token", data=token_data, headers=token_headers)

    
    
    global accessToken
    accessToken = r.json()["access_token"]

    global refreshToken
    refreshToken = r.json()["refresh_token"]

    print('--access token: '+ accessToken) 
    print('--refresh token: '+ refreshToken)


def openWebdriver():

    driverGlobal.get('https://www.instagram.com/accounts/login')

    cookieDialog = WebDriverWait(driverGlobal, 10).until(EC.element_to_be_clickable((By.XPATH, '//*[@role="dialog"]')))
    btns = cookieDialog.find_elements(By.TAG_NAME, "button")
    btns[7].click() #might vary in future

    time.sleep(3)

    username = driverGlobal.find_element(By.NAME, "username").send_keys(instagramUsername)
    password = driverGlobal.find_element(By.NAME, "password").send_keys(instagramPassword)

    time.sleep(3)

    logIn = WebDriverWait(driverGlobal, 10).until(EC.element_to_be_clickable((By.CSS_SELECTOR, "button[type='submit']"))).click()
    
    time.sleep(10)

    threadUpdateBio = Thread(target=updateBio)
    threadUpdateBio.start()
    threadUpdateBio.join()


def updateBio():

    while True:

        currentlyPlaying = getCurrentlyPlaying()

        if currentlyPlaying == None:
            time.sleep(120)
            continue
        
        driverGlobal.get('https://www.instagram.com/accounts/edit/')

        time.sleep(5)

        bio = WebDriverWait(driverGlobal, 10).until(EC.element_to_be_clickable((By.ID, 'pepBio')))
        bio.clear()
        bio.send_keys(currentlyPlaying)

        time.sleep(2)

        btnSendList = driverGlobal.find_elements(By.XPATH, "//div[@role = 'button']")
        btnSendList[2].click()

        time.sleep(120)


def getCurrentlyPlaying():
    
    #documentation:
    #https://developer.spotify.com/documentation/web-api/reference/get-the-users-currently-playing-track
    #https://developer.spotify.com/documentation/web-api/concepts/api-calls

    response = requests.get(
        'https://api.spotify.com/v1/me/player/currently-playing',
        headers={
            "Authorization": f"Bearer {accessToken}"
        }
    )

    if response.status_code == 200:

        try:

            jsonResp = response.json()

            if jsonResp['is_playing'] != True :
                print("Paused\n////////////////////")
                return None

            trackName = jsonResp['item']['name']
            artists = [artist for artist in jsonResp['item']['artists']]
            artistNames = ', '.join([artist['name'] for artist in artists])
            currentTrackInfo = {'track': trackName, 'artist': artistNames}
            generatedBio = generateBio(currentTrackInfo)

            print(generatedBio + "\n////////////////////")
            return generatedBio

        except:

            print("No information on currently Playing song.\n////////////////////")
            return None

    else:

        print("Request failed. Status code", response.status_code)

        if response.status_code == 401:
            refreshAuthToken()
            print("Authorization code refreshed.\n////////////////////")
        return None


def generateBio(bioInfos):
    
    bio_infos = bioInfos['track'] + " - " + bioInfos['artist']
    now = datetime.now()
    timeBio = now.strftime("%H:%M:%S, %d.%m.%Y")
    return bio_infos + '\n' + timeBio 


def refreshAuthToken():

    while True:
    
        encoded_credentials = base64.b64encode(clientID.encode() + b':' + clientSecret.encode()).decode("utf-8")

        token_headers = {
            "Authorization": "Basic " + encoded_credentials,
            "Content-Type": "application/x-www-form-urlencoded"
        }

        token_data = {
            "grant_type": "refresh_token",
            "refresh_token": refreshToken,
        }

        r = requests.post("https://accounts.spotify.com/api/token", data=token_data, headers=token_headers)

        global accessToken
        accessToken = r.json()["access_token"]


def main():
    authorizeApp()
    getAuthToken()
    openWebdriver()


if __name__ == '__main__':
    main()