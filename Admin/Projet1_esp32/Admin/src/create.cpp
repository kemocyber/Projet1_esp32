//include
#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <SPI.h>
#include <MFRC522.h>
#include <ArduinoJson.h>


// define
#define reseau      "RouteurCadeau"
#define MDP         "CadeauRouteur"
#define TOKENAPI    "https://guardia-api.iadjedj.ovh/token?exp=120"
#define CREATE_URL  "https://guardia-api.iadjedj.ovh/create_badge"
#define RST_PIN     D1
#define SS_PIN      D4
#define ROUGE       D3
#define VERT        D2


MFRC522 mfrc522(SS_PIN, RST_PIN);
WiFiClientSecure client;
HTTPClient http;

void sendBadgeToAPI(unsigned long badgeId);

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

unsigned long convertUIDToLong(String cardUID) {
  unsigned long badgeId = 0;
  for (byte i = 0; i < cardUID.length() / 2; i++) {
    badgeId = badgeId * 256 + strtol(cardUID.substring(i * 2, i * 2 + 2).c_str(), NULL, 16);
  }
  return badgeId;
}

void setup() {
  Serial.begin(115200);

  WiFi.begin(reseau, MDP);
  while (WiFi.status() != WL_CONNECTED) {
    Serial.println("Connexion Wi-Fi...");
    delay(1000);
  }
  Serial.println("Connexion Wi-Fi réussie");

  SPI.begin();
  mfrc522.PCD_Init();
  Serial.println("Approchez une carte...");

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
  delay(1000);
}

void loop() {
  if (mfrc522.PICC_IsNewCardPresent()) {
    if (mfrc522.PICC_ReadCardSerial()) {
      digitalWrite(ROUGE, LOW);  
      digitalWrite(VERT, HIGH);  

      Serial.println("Carte détectée !");
      String cardUID = "";
     
      for (byte i = 0; i < mfrc522.uid.size; i++) {
        cardUID += String(mfrc522.uid.uidByte[i], HEX);  
        Serial.print(mfrc522.uid.uidByte[i], HEX);
        Serial.print(" ");
      }
      Serial.println();
     
      unsigned long badgeId = convertUIDToLong(cardUID);

      // Afficher l'ID sous forme d'entier
      Serial.print("ID du badge (entier) : ");
      Serial.println(badgeId);

      // Envoyer les données à l'API
      sendBadgeToAPI(badgeId);

      delay(1000);  
    }
  } else {
    digitalWrite(VERT, LOW);
    digitalWrite(ROUGE, HIGH);  // LED rouge si aucune carte n'est détectée
  }
}


void sendBadgeToAPI(unsigned long badgeId) {
  if (WiFi.status() == WL_CONNECTED) {
    http.begin(CREATE_URL);
    http.addHeader("Content-Type", "application/json");

    // Créer le JSON avec l'ID du badge et le niveau
    JsonDocument doc;
    doc["badge_id"] = badgeId;
    doc["level"] = "user";
    String jsonData;
    serializeJson(doc, jsonData);
    http.addHeader("Content-Length", String(jsonData.length()));  // Indiquer la taille
    int httpCode = http.POST(jsonData);

    if (httpCode > 0) {
        String payload = http.getString();
        Serial.println("Réponse de l'API:");
        Serial.println(payload);
    } else {
        Serial.printf("Erreur lors de l'envoi de la requête: %d\n", httpCode);
    }
    http.end();
  } else {
      Serial.println("Erreur: Pas de connexion Wi-Fi !");
  }
}
