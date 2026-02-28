#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include <Crypto.h>
#include <AES.h>
#include <CTR.h>
#include <mbedtls/gcm.h>
#include "esp_system.h"
#include "secrets.h"
#include "esp_heap_caps.h"

WiFiClientSecure wifi_client;
PubSubClient mqtt(wifi_client);

// MQTT payload buffer sized for:
// - 1 byte flag
// - nonce/iv overhead
// - up to 2KB plaintext/ciphertext
// - tag (GCM)

static uint8_t mqttPayload[2500];

// AES-GCM framing constants
static const int GCM_NONCE_LEN = 12;   //GCM nonce size
static const int GCM_TAG_LEN   = 16;   //GCM authentication tag size
static const int GCM_THRESHOLD = 1024;

/**
 * AES-GCM encryption using mbedTLS:
 * - Provides confidentiality + integrity (tamper detection via tag verification on receiver)
 * - No AAD in this implementation (nullptr, 0)
 *
 * Output:
 * - ct[]: ciphertext
 * - tag[]: auth tag (GCM_TAG_LEN)
 */
static bool gcm_encrypt(
  const uint8_t* key, size_t key_len,
  const uint8_t* nonce, size_t nonce_len,
  const uint8_t* pt, size_t pt_len,
  uint8_t* ct,
  uint8_t* tag, size_t tag_len
) {
  mbedtls_gcm_context ctx;
  mbedtls_gcm_init(&ctx);

  // Configure AES key (bits = key_len * 8)
  int rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, (unsigned int)(key_len * 8));
  if (rc != 0) { mbedtls_gcm_free(&ctx); return false; }

  // Encrypt and compute authentication tag
  rc = mbedtls_gcm_crypt_and_tag(
    &ctx, MBEDTLS_GCM_ENCRYPT,
    pt_len,
    nonce, nonce_len,
    nullptr, 0,
    pt,
    ct,
    tag_len, tag
  );

  mbedtls_gcm_free(&ctx);
  return rc == 0;
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

  mqtt.setBufferSize(sizeof(mqttPayload));

  mqtt.setKeepAlive(60);

  randomSeed(esp_random());
}

void loop() {
  if (!mqtt.connected()) {
    Serial.println("Connecting to MQTT...");
    if (mqtt.connect("esp32-sender")) {
      Serial.println("MQTT connected");
    } else {
      Serial.print("MQTT connect failed, rc=");
      Serial.println(mqtt.state());
      delay(2000);
      return;
    }
  }

  for (int i = 0; i < 50; i++) {
    mqtt.loop();
    delay(100);
  }

  // Message sequence ID for replay detection / traceability
  static uint32_t msg_id = 0;
  msg_id++;

  // Generate a random plaintext payload (used for size-based performance measurements)
  int payloadLen = random(256, 2048);

  String plainText;
  plainText.reserve(payloadLen);

  // Embed a small header for debugging and replay checks:
  // MSG:<id> used by receiver to detect replay and validate decrypt output
  // TS:<millis> sender timestamp (optional: end-to-end timing if receiver uses it)
  plainText += "MSG:";
  plainText += String(msg_id);
  plainText += ";TS:";
  plainText += String(millis());
  plainText += ";";

  // Fill the remainder with printable chars (avoid CR/LF)
  while ((int)plainText.length() < payloadLen) {
    char c = (char)random(32, 126);
    if (c == '\n' || c == '\r') c = '_';
    plainText += c;
  }

  int len = plainText.length();

  // Always-on heap snapshot (easy visibility + helps validate memory behaviour over time)
  // - free_heap: instantaneous free heap
  // - min_free_heap: low-water mark since boot (peak memory pressure indicator)
  Serial.printf(
    "HeapSnapshot: msg_id=%lu len=%d free_heap=%lu min_free_heap=%lu\n",
    (unsigned long)msg_id, len,
    (unsigned long)ESP.getFreeHeap(),
    (unsigned long)heap_caps_get_minimum_free_size(MALLOC_CAP_8BIT)
  );

  // Adaptive encryption decision:
  // - FORCE_ENCRYPT=true => always encrypt (static baseline)
  // - otherwise encrypt only when len > ENCRYPTION_THRESHOLD
  bool doEncrypt = FORCE_ENCRYPT || (len > ENCRYPTION_THRESHOLD);

  int payload_len = 0;

  if (doEncrypt) {
    // Decide which algorithm based on size:
    // - CTR for smaller payloads
    // - GCM for larger payloads (adds integrity; more secure framing)
    bool useGcm = (len >= GCM_THRESHOLD);

    if (!useGcm) {
      // AES-CTR
      // [0]      = 1 (CTR)
      // [1..16]  = IV (16 bytes)
      // [17..]   = ciphertext
      byte iv[16];
      for (int i = 0; i < 16; i++) iv[i] = random(0, 256);

      mqttPayload[0] = 1;
      memcpy(mqttPayload + 1, iv, 16);

      CTR<AES128> ctr;
      ctr.clear();
      ctr.setKey((byte*)AES_KEY_128, sizeof(AES_KEY_128));
      ctr.setIV(iv, sizeof(iv));

      // Measure heap + encryption time
      uint32_t heap_before = ESP.getFreeHeap();
      unsigned long t0 = micros();

      ctr.encrypt(mqttPayload + 17, (const byte*)plainText.c_str(), len);

      unsigned long t1 = micros();
      uint32_t heap_after = ESP.getFreeHeap();
      uint32_t heap_min_after = heap_caps_get_minimum_free_size(MALLOC_CAP_8BIT);

      payload_len = 1 + 16 + len;

      // Dataset log line (per message)
      Serial.printf(
        "Sender: msg_id=%lu payload_len=%d algorithm=CTR enc_time_us=%lu heap_before=%lu heap_after=%lu heap_min=%lu\n",
        (unsigned long)msg_id, len, (unsigned long)(t1 - t0),
        (unsigned long)heap_before, (unsigned long)heap_after, (unsigned long)heap_min_after
      );

    } else {
      // AES-GCM
      // Framing:
      // [0]          = 2 (GCM)
      // [1..12]      = nonce (12 bytes)
      // [13..13+len) = ciphertext
      // [end-16..end)= tag (16 bytes)
      // Note: GCM provides confidentiality + integrity (tamper detected via tag)
      uint8_t nonce[GCM_NONCE_LEN];
      for (int i = 0; i < GCM_NONCE_LEN; i++) nonce[i] = (uint8_t)random(0, 256);

      mqttPayload[0] = 2;
      memcpy(mqttPayload + 1, nonce, GCM_NONCE_LEN);

      uint8_t* ct_ptr = mqttPayload + 1 + GCM_NONCE_LEN;
      uint8_t tag[GCM_TAG_LEN];

      // Measure heap + encryption time
      uint32_t heap_before = ESP.getFreeHeap();
      unsigned long t0 = micros();

      bool ok = gcm_encrypt(
        AES_KEY_128, sizeof(AES_KEY_128),
        nonce, sizeof(nonce),
        (const uint8_t*)plainText.c_str(), len,
        ct_ptr,
        tag, sizeof(tag)
      );

      unsigned long t1 = micros();
      uint32_t heap_after = ESP.getFreeHeap();
      uint32_t heap_min_after = heap_caps_get_minimum_free_size(MALLOC_CAP_8BIT);

      if (!ok) {
        Serial.println("Sender: GCM encrypt failed");
        return;
      }

      memcpy(ct_ptr + len, tag, GCM_TAG_LEN);

      payload_len = 1 + GCM_NONCE_LEN + len + GCM_TAG_LEN;

      // Dataset serial print
      Serial.printf(
        "Sender: msg_id=%lu payload_len=%d algorithm=GCM enc_time_us=%lu heap_before=%lu heap_after=%lu heap_min=%lu\n",
        (unsigned long)msg_id, len, (unsigned long)(t1 - t0),
        (unsigned long)heap_before, (unsigned long)heap_after, (unsigned long)heap_min_after
      );
    }

  } else {
    // ---------------- Plaintext (flag=0) ----------------
    // No longer used just for the record
    // [0]    = 0
    // [1..]  = plaintext bytes
    mqttPayload[0] = 0;
    memcpy(mqttPayload + 1, plainText.c_str(), len);
    payload_len = 1 + len;

    uint32_t heap_now = ESP.getFreeHeap();
    uint32_t heap_min_now = heap_caps_get_minimum_free_size(MALLOC_CAP_8BIT);

    Serial.printf(
      "Sender: msg_id=%lu payload_len=%d encrypted=0 heap_now=%lu heap_min=%lu\n",
      (unsigned long)msg_id, len,
      (unsigned long)heap_now, (unsigned long)heap_min_now
    );
  }

  // Publish binary to AWS IoT Core topic (bin
  if (mqtt.publish(TOPIC_DATA, mqttPayload, payload_len)) {
    Serial.println("Message published");
  } else {
    Serial.println("Publish failed");
  }

  mqtt.loop();
}