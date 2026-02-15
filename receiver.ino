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

// Buffer for decrypted/plaintext (keep <= your max payloadLen)
static char plainBuf[200];

static uint32_t last_msg_id = 0;

// Extract msg_id from plaintext like: "MSG:123;TS:456;"
static bool extractMsgId(const char* s, uint32_t &outId) {
  const char* p = strstr(s, "MSG:");
  if (!p) return false;
  p += 4;
  char* endp = nullptr;
  unsigned long v = strtoul(p, &endp, 10);
  if (endp == p) return false;
  outId = (uint32_t)v;
  return true;
}

static void onMessage(char* topic, byte* payload, unsigned int length) {
  if (length < 2) return; // must have at least flag + 1 byte

  byte flag = payload[0];
  int plainLen = 0;

  if (flag == 1) {
    // Encrypted: [flag][IV 16][ciphertext...]
    if (length < 1 + 16 + 1) return;

    byte iv[16];
    memcpy(iv, payload + 1, 16);

    const byte* cipher = payload + 17;
    int cipherLen = (int)length - 17;

    if (cipherLen >= (int)sizeof(plainBuf)) cipherLen = sizeof(plainBuf) - 1;

    CTR<AES128> ctr;
    ctr.clear();
    ctr.setKey(AES_KEY_128, sizeof(AES_KEY_128));
    ctr.setIV(iv, sizeof(iv));

    unsigned long t0 = micros();
    ctr.decrypt((byte*)plainBuf, cipher, cipherLen);
    unsigned long t1 = micros();

    plainLen = cipherLen;
    plainBuf[plainLen] = '\0';

    uint32_t msg_id = 0;
    bool ok = extractMsgId(plainBuf, msg_id);

    // simple replay check
    bool replay = ok && (msg_id <= last_msg_id);
    if (ok && !replay) last_msg_id = msg_id;

    Serial.printf("Recv: enc=1 bytes=%u dec_time_us=%lu msg_id=%lu replay=%d\n",
                  length, (unsigned long)(t1 - t0),
                  (unsigned long)(ok ? msg_id : 0), replay ? 1 : 0);

    Serial.printf("Plain: %s\n", plainBuf);

  } else {
    // Plaintext: [flag][plaintext...]
    int dataLen = (int)length - 1;
    if (dataLen >= (int)sizeof(plainBuf)) dataLen = sizeof(plainBuf) - 1;

    memcpy(plainBuf, payload + 1, dataLen);
    plainBuf[dataLen] = '\0';
    plainLen = dataLen;

    uint32_t msg_id = 0;
    bool ok = extractMsgId(plainBuf, msg_id);

    bool replay = ok && (msg_id <= last_msg_id);
    if (ok && !replay) last_msg_id = msg_id;

    Serial.printf("Recv: enc=0 bytes=%u msg_id=%lu replay=%d\n",
                  length, (unsigned long)(ok ? msg_id : 0), replay ? 1 : 0);
    Serial.printf("Plain: %s\n", plainBuf);
  }
}

static void connectMqtt() {
  while (!mqtt.connected()) {
    Serial.println("Connecting to MQTT...");
    if (mqtt.connect("esp32-receiver")) { // must be different from sender
      Serial.println("MQTT connected");
      mqtt.subscribe(TOPIC_DATA);
      Serial.println("Subscribed to TOPIC_DATA");
    } else {
      Serial.print("MQTT connect failed, rc=");
      Serial.println(mqtt.state());
      delay(2000);
    }
  }
}

void setup() {
  Serial.begin(115200);
  delay(100);

  WiFi.begin(WIFI_SSID, WIFI_PASS);
  Serial.print("Connecting to WiFi");
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("Connection established");

  wifi_client.setCACert(AWS_ROOT_CA);
  wifi_client.setCertificate(AWS_DEVICE_CERT);
  wifi_client.setPrivateKey(AWS_PRIVATE_KEY);

  WiFi.setSleep(false);

  mqtt.setServer(AWS_IOT_ENDPOINT, AWS_IOT_PORT);
  mqtt.setBufferSize(256);
  mqtt.setKeepAlive(60);

  mqtt.setCallback(onMessage);

  connectMqtt();
}

void loop() {
  if (!mqtt.connected()) {
    connectMqtt();
  }
  mqtt.loop();
}
