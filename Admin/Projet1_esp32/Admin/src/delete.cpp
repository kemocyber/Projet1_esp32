//inclure
#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <SPI.h>
#include <MFRC522.h>
#include <ArduinoJson.h>


//define
#define reseau      "RouteurCadeau"
#define MDP         "CadeauRouteur"
#define URLAPI      "https://guardia-api.iadjedj.ovh/unsecure/docs#/"
#define DELETE_BADGE   "https://guardia-api.iadjedj.ovh/unsecure/delete_badge?badge_id="
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
  Serial.println("Approchez une carte RFID...");
  delay(1000);  
 
  pinMode(VERT, OUTPUT);
  pinMode(ROUGE, OUTPUT);
  digitalWrite(VERT, LOW);
  digitalWrite(ROUGE, LOW);
}


void loop() {
   if (mfrc522.PICC_IsNewCardPresent()) {
    if (mfrc522.PICC_ReadCardSerial()) {
      digitalWrite(ROUGE, LOW);
      digitalWrite(VERT, HIGH);


      Serial.print("UID de la carte : ");
      String cardUID = "";
      for (byte i = 0; i < mfrc522.uid.size; i++) {
        cardUID += String(mfrc522.uid.uidByte[i], HEX);
        Serial.print(mfrc522.uid.uidByte[i], HEX);
        Serial.print(" ");
      }
      Serial.println(cardUID);
       
      unsigned long badgeId = 0;
      for (byte i = 0; i < cardUID.length() / 2; i++) {
        badgeId = badgeId * 256 + strtol(cardUID.substring(i * 2, i * 2 + 2).c_str(), NULL, 16);
      }
      Serial.println(badgeId);
     
      String url = String(DELETE_BADGE) + String(badgeId);
      http.begin(url.c_str());
      int httpCode = http.sendRequest("DELETE");


      if (httpCode > 0) {
    String payload = http.getString();  
    Serial.println("Réponse reçue de l'API:");
    Serial.println(payload);
} else {
    Serial.printf("Erreur lors de l'envoi de la requête: %d\n", httpCode);
}


http.end();
  delay(100);
}
   }
}
