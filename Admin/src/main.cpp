#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <SPI.h>
#include <MFRC522.h>
#include <ArduinoJson.h>

#define reseau      "RouteurCadeau"
#define MDP         "CadeauRouteur"
#define TOKENAPI    "https://guardia-api.iadjedj.ovh/token?exp=120"
#define CHECKAPI    "https://guardia-api.iadjedj.ovh/check_badge?badge_id="
#define RST_PIN     D1
#define SS_PIN      D4
#define ROUGE       D3
#define VERT        D2

MFRC522 mfrc522(SS_PIN, RST_PIN);

WiFiClientSecure client;
HTTPClient http;

String accessToken = "";  

String getJwtToken() {
  String username = "admin_123";  
  String password = "password_456"; 
  String payload = "grant_type=password&username=" + username + "&password=" + password + "&scope=&client_id=&client_secret=";

  client.setInsecure(); 

  http.begin(client, TOKENAPI);  
  http.addHeader("Content-Type", "application/x-www-form-urlencoded");  
  http.addHeader("accept", "application/json");  

  int httpCode = http.POST(payload);

  if (httpCode == 200) {
    String response = http.getString();
    
    StaticJsonDocument<200> doc;
    DeserializationError error = deserializeJson(doc, response);
    if (error) {
      Serial.println("Erreur de désérialisation JSON");
      return "";
    }

    String token = doc["access_token"].as<String>();
    return token;
  } else {
    Serial.print("Erreur lors de la récupération du token: ");
    Serial.println(httpCode);
    return "";
  }
}

void setup() {
  Serial.begin(9600);
  WiFi.begin(reseau, MDP);
  
  while (WiFi.status() != WL_CONNECTED) {
    Serial.println("Connexion Wifi...");
    delay(500);
  }
  Serial.println("Connexion Wifi réussie");

  SPI.begin(D8 , D9 , D10 , SS_PIN);  // SCK, MISO, MOSI, SS  
  mfrc522.PCD_Init();  
  Serial.println("Approchez une carte...");
  delay(1000);  

  pinMode(VERT, OUTPUT);
  pinMode(ROUGE, OUTPUT);
  digitalWrite(VERT, LOW);
  digitalWrite(ROUGE, LOW);

  
  accessToken = getJwtToken();
  if (accessToken != "") {
    Serial.println("Token JWT récupéré avec succès");
  } else {
    Serial.println("Erreur de récupération du token");
  }
}

void loop() {
   if (mfrc522.PICC_IsNewCardPresent()) {
    if (mfrc522.PICC_ReadCardSerial()) {
      Serial.print("UID de la carte : ");
      String cardUID = "";
      for (byte i = 0; i < mfrc522.uid.size; i++) {
        cardUID += String(mfrc522.uid.uidByte[i], HEX);
        Serial.print(mfrc522.uid.uidByte[i], HEX);
        Serial.print(" ");
      }
      
      unsigned long badgeId = 0;
      for (byte i = 0; i < cardUID.length() / 2; i++) {
        badgeId = badgeId * 256 + strtol(cardUID.substring(i * 2, i * 2 + 2).c_str(), NULL, 16);
      }
      Serial.println(badgeId);

     
      String url = String(CHECKAPI) + String(badgeId);
      
    
      if (accessToken == "") {
        Serial.println("Erreur: Token d'accès manquant !");
        return;
      }

     
      http.begin(url.c_str());
      http.addHeader("Authorization", "Bearer " + accessToken);  

      int httpCode = http.GET();  

      if (httpCode > 0) {
        String payload = http.getString();  
        Serial.println("Réponse reçue de l'API:");

        JsonDocument doc;
        DeserializationError error = deserializeJson(doc, payload);

        if (error) {
          Serial.print("deserializeJson() failed: ");
          Serial.println(error.c_str());
          return;
        }      

        const char* level = doc["level"];
        long long badge_id = doc["badge_id"];

        Serial.print("Level: ");
        Serial.println(level);

        if (strcmp(level, "user") == 0 || strcmp(level, "admin") == 0) {
          Serial.println("Accès autorisé");
          digitalWrite(VERT, HIGH);
          digitalWrite(ROUGE, LOW);
          delay(2000);
        } else {
          Serial.println("Badge inconnu ou non autorisé.");
          digitalWrite(VERT, LOW);
          digitalWrite(ROUGE, HIGH);
          delay(2000);
        }


      } else {
        Serial.println("Erreur lors de la requête HTTP");
        Serial.print("Code d'erreur HTTP: ");
        Serial.println(httpCode);
      }
      http.end(); 
      digitalWrite(VERT, LOW);
      digitalWrite(ROUGE, LOW); 
    }
  }
  delay(100);
}
