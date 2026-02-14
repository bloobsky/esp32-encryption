#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include <Crypto.h>
#include <AES.h>
#include <CTR.h>
#include "esp_system.h"
#include "secrets.h"


WiFiClientSecure wifi_client;
PubSubClient mqtt(wifi_client);

void setup() {
  Serial.begin(115200);
  delay(100);

  // Connect WiFi
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  Serial.print("Connecting to WiFi");
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("Connection established");

  // Configure TLS certs (from secrets.h)
  wifi_client.setCACert(AWS_ROOT_CA);
  wifi_client.setCertificate(AWS_DEVICE_CERT);
  wifi_client.setPrivateKey(AWS_PRIVATE_KEY);

  // Keep Wifi Stable
  WiFi.setSleep(false);

  //Setup MQTT
  mqtt.setServer(AWS_IOT_ENDPOINT, AWS_IOT_PORT);
  mqtt.setBufferSize(256);
  mqtt.setKeepAlive(60);

  // RNG seed (ESP32 hardware RNG)
  randomSeed(esp_random());
}

void loop() {
  if (!mqtt.connected()) {
    Serial.println("Connecting to MQTT...");
    if (mqtt.connect("esp32-sender")) { // This is client ID unique for device
      Serial.println("MQTT connected");
    } else {
      Serial.print("MQTT connect failed, rc=");
      Serial.println(mqtt.state());
      delay(2000);
      return;
    }
  }

  // Kepp mqtt alive with pacing of 5s
  for (int i = 0; i < 50; i++) {  
    mqtt.loop();
    delay(100);
  }

  static uint32_t msg_id = 0;
  msg_id++;

  // Generate variable size plain text to excercise adaptive encryption. 
  int payloadLen = random(20, 140);
  String plainText;
  plainText.reserve(payloadLen);

  // Minimal header embedded in plaintext for debugging and analysis
  // - msg_id traceability
  // - TS sender timestamp for potential end-to-end latency (if receiver uses it
  plainText += "MSG:";
  plainText += String(msg_id);
  plainText += ";TS:";
  plainText += String(millis());
  plainText += ";";

  while ((int)plainText.length() < payloadLen) {
    plainText += char(random(32, 126));
  }

  int len = plainText.length();
  // adaptive encryption switch
  bool doEncrypt = FORCE_ENCRYPT || (len > ENCRYPTION_THRESHOLD); 

  //   MQTT binary message format (simple and fast):
  //   [0]        : flag (0 = plaintext, 1 = encrypted)
  //   [1..16]    : IV (16 bytes) if encrypted, otherwise unused/absent
  //   [17..]     : ciphertext (CTR) OR plaintext (if flag=0, stored at [1..])
  //   Note: CTR provides confidentiality but NOT integrity. (Tamper detection requires MAC/AEAD)
  byte mqttPayload[256];
  int payload_len = 0;

  if (doEncrypt) {
    byte iv[16];
    for (int i = 0; i < 16; i++) iv[i] = random(0, 256);

    mqttPayload[0] = 1;
    memcpy(mqttPayload + 1, iv, 16);

    CTR<AES128> ctr;
    ctr.clear();
    ctr.setKey(AES_KEY_128, sizeof(AES_KEY_128));
    ctr.setIV(iv, sizeof(iv));

    int heap_before = ESP.getFreeHeap();
    unsigned long t0 = micros();

    ctr.encrypt(mqttPayload + 17, (const byte*)plainText.c_str(), len);

    unsigned long t1 = micros();
    int heap_after = ESP.getFreeHeap();

    Serial.printf(
      "Sender: msg_id=%lu payload_len=%d encrypted=1 enc_time_us=%lu heap_before=%d heap_after=%d\n",
      (unsigned long)msg_id, len, (unsigned long)(t1 - t0), heap_before, heap_after
    );

    payload_len = 1 + 16 + len;

  } 
  else {
    mqttPayload[0] = 0;
    memcpy(mqttPayload + 1, plainText.c_str(), len);

    Serial.printf(
      "Sender: msg_id=%lu payload_len=%d encrypted=0\n",
      (unsigned long)msg_id, len
    );

    payload_len = 1 + len;
  }
  // Publish to AWS Iot Core
  if (mqtt.publish(TOPIC_DATA, mqttPayload, payload_len)) {
    Serial.println("Message published");
  } 
  else {
    Serial.println("Publish failed");
  }

  mqtt.loop();
  
}
