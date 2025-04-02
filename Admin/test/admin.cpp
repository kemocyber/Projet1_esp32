#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <SPI.h>
#include <MFRC522.h>
#include <ArduinoJson.h>

#define reseau      "RouteurCadeau"
#define MDP         "CadeauRouteur"
//#define TOKENAPI    "https://guardia-api.iadjedj.ovh/token?exp=120"
#define CHECKAPI    "https://guardia-api.iadjedj.ovh/unsecure/check_badge?badge_id="
#define RST_PIN     D1
#define SS_PIN      D4
#define ROUGE       D3
#define VERT        D2

MFRC522 mfrc522(SS_PIN, RST_PIN);

HTTPClient http;


void setup() {
  Serial.begin(9600);
  WiFi.begin(reseau, MDP);
  
  while (WiFi.status() != WL_CONNECTED) {
    Serial.println("Connexion Wifi...");
    delay(500);
  }
  Serial.println("Connexion Wifi réussi");

  SPI.begin(D8 , D9 , D10 , SS_PIN);  // SCK, MISO, MOSI, SS  
  mfrc522.PCD_Init();  
  Serial.println("Approchez une carte...");
  delay(1000);  

  pinMode(VERT, OUTPUT);
  pinMode(ROUGE, OUTPUT);
  digitalWrite(VERT, LOW);
  digitalWrite(ROUGE, LOW);

  // Obtenir le JWT Token au début
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
      http.begin(url.c_str());
      int httpCode = http.GET(); 

      if (httpCode > 0) {
        String payload = http.getString();
        Serial.println("Réponse brute de l'API :");
        Serial.println(payload);  


        JsonDocument doc;
        DeserializationError error = deserializeJson(doc, payload);


        if (error) {
          Serial.print("deserializeJson() failed: ");
          Serial.println(error.c_str());
          return;
        }      
        const char* level = doc["level"];
        Serial.println(level);


        if (String(level) == "admin") {
          digitalWrite(VERT, HIGH);
          digitalWrite(ROUGE, LOW);
          Serial.println("Accès autorisé !");
          delay(100);
          digitalWrite(VERT, LOW);
          // Envoi d'une requête HTTP à un serveur pour exécuter un script Python
          String serverUrl = "http://192.168.238.103:5000/run_script"; // Assurez-vous que le serveur Flask fonctionne sur cette adresse
          // Utilise WiFiClient (pas WiFiClientSecure)
          WiFiClient client;
          http.begin(client, serverUrl); // Assurez-vous d'utiliser le bon client HTTP
          int httpCode = http.GET();
          Serial.print("Code de réponse HTTP : ");
          Serial.println(httpCode);


          String payload = http.getString();
          Serial.println("Réponse du serveur : ");
          Serial.println(payload);
        } else {
          digitalWrite(VERT, LOW);
          digitalWrite(ROUGE, HIGH);
          Serial.println("Accès refusé, permissions insuffisantes !");
          delay(100);
          digitalWrite(ROUGE, LOW);
        }
      } else {
        Serial.println("Erreur lors de la requête HTTP");
        Serial.println(httpCode);
      }


      http.end();  
    }
  }
  delay(100);
}
