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

// Big buffer to handle 2KB plaintext after decrypt
static char plainBuf[2500];

// Replay tracking
static uint32_t last_msg_id = 0;

// AES-GCM framing constants
static const int GCM_NONCE_LEN = 12;
static const int GCM_TAG_LEN   = 16;

// META RX for testing and analysis
static void publishMetaRx(uint32_t msg_id, int enc, const char* algorithm, unsigned int bytes,
                          unsigned long dec_time_us, int replay, int auth_fail,
                          uint32_t heap_before, uint32_t heap_after, uint32_t heap_min_after) {
  char meta[512];
  snprintf(meta, sizeof(meta),
    "{"
      "\"side\":\"rx\","
      "\"msg_id\":%lu,"
      "\"ts_ms\":%lu,"
      "\"enc\":%d,"
      "\"algorithm\":\"%s\","
      "\"bytes\":%u,"
      "\"dec_time_us\":%lu,"
      "\"replay\":%d,"
      "\"auth_fail\":%d,"
      "\"heap_before\":%lu,"
      "\"heap_after\":%lu,"
      "\"heap_min\":%lu"
    "}",
    (unsigned long)msg_id,
    (unsigned long)millis(),
    enc,
    algorithm,
    bytes,
    (unsigned long)dec_time_us,
    replay,
    auth_fail,
    (unsigned long)heap_before,
    (unsigned long)heap_after,
    (unsigned long)heap_min_after
  );

  mqtt.publish(TOPIC_META_RX, meta);
}

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

// AES-GCM decrypt + verify (no AAD)
static bool gcm_decrypt_verify(
  const uint8_t* key, size_t key_len,
  const uint8_t* nonce, size_t nonce_len,
  const uint8_t* ct, size_t ct_len,
  const uint8_t* tag, size_t tag_len,
  uint8_t* pt_out
) {
  mbedtls_gcm_context ctx;
  mbedtls_gcm_init(&ctx);

  int rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, (unsigned int)(key_len * 8));
  if (rc != 0) { mbedtls_gcm_free(&ctx); return false; }

  rc = mbedtls_gcm_auth_decrypt(
    &ctx,
    ct_len,
    nonce, nonce_len,
    nullptr, 0,
    tag, tag_len,
    ct,
    pt_out
  );

  mbedtls_gcm_free(&ctx);
  return rc == 0;
}

static void onMessage(char* topic, byte* payload, unsigned int length) {
  if (length < 2) {
    Serial.printf("Recv: drop reason=too_short bytes=%u\n", length);
    return;
  }

  byte flag = payload[0];

  // ---------------------------------------------------------------------------
  // flag=1: AES-CTR
  // Frame: [1][IV 16][ciphertext...]
  // ---------------------------------------------------------------------------
  if (flag == 1) {
    if (length < 1 + 16 + 1) {
      Serial.printf("Recv: drop reason=short_ctr_frame bytes=%u\n", length);
      return;
    }

    byte iv[16];
    memcpy(iv, payload + 1, 16);

    const byte* cipher = payload + 17;
    int cipherLen = (int)length - 17;

    if (cipherLen >= (int)sizeof(plainBuf)) cipherLen = sizeof(plainBuf) - 1;

    CTR<AES128> ctr;
    ctr.clear();
    ctr.setKey(AES_KEY_128, sizeof(AES_KEY_128));
    ctr.setIV(iv, sizeof(iv));

    // heap + timing instrumentation
    uint32_t heap_before = ESP.getFreeHeap();
    unsigned long t0 = micros();
    ctr.decrypt((byte*)plainBuf, cipher, cipherLen);
    unsigned long t1 = micros();
    uint32_t heap_after = ESP.getFreeHeap();
    uint32_t heap_min_after = heap_caps_get_minimum_free_size(MALLOC_CAP_8BIT);

    plainBuf[cipherLen] = '\0';

    uint32_t msg_id = 0;
    bool ok = extractMsgId(plainBuf, msg_id);

    bool replay = ok && (msg_id <= last_msg_id);
    if (ok && !replay) last_msg_id = msg_id;

    Serial.printf(
      "Recv: enc=1 algorithm=CTR bytes=%u dec_time_us=%lu msg_id=%lu replay=%d heap_before=%lu heap_after=%lu heap_min=%lu\n",
      length, (unsigned long)(t1 - t0),
      (unsigned long)(ok ? msg_id : 0), replay ? 1 : 0,
      (unsigned long)heap_before, (unsigned long)heap_after, (unsigned long)heap_min_after
    );

    // Publish metadata
    publishMetaRx(ok ? msg_id : 0, 1, "CTR", length, (t1 - t0), replay ? 1 : 0, 0,
                  heap_before, heap_after, heap_min_after);

    Serial.printf("Plain: %s\n", plainBuf);
    return;
  }

  // ---------------------------------------------------------------------------
  // flag=2: AES-GCM
  // Frame: [2][nonce 12][ciphertext...][tag 16]
  // ---------------------------------------------------------------------------
  if (flag == 2) {
    if (length < 1 + GCM_NONCE_LEN + 1 + GCM_TAG_LEN) {
      Serial.printf("Recv: drop reason=short_gcm_frame bytes=%u\n", length);
      return;
    }

    const uint8_t* nonce = (const uint8_t*)(payload + 1);
    const uint8_t* ct    = (const uint8_t*)(payload + 1 + GCM_NONCE_LEN);

    int ct_and_tag_len = (int)length - (1 + GCM_NONCE_LEN);
    int ct_len = ct_and_tag_len - GCM_TAG_LEN;
    if (ct_len <= 0) {
      Serial.printf("Recv: drop reason=gcm_ct_len_invalid bytes=%u\n", length);
      return;
    }

    const uint8_t* tag = ct + ct_len;

    if (ct_len >= (int)sizeof(plainBuf)) ct_len = sizeof(plainBuf) - 1;

    // heap + timing instrumentation
    uint32_t heap_before = ESP.getFreeHeap();
    unsigned long t0 = micros();
    bool ok_auth = gcm_decrypt_verify(
      AES_KEY_128, sizeof(AES_KEY_128),
      nonce, GCM_NONCE_LEN,
      ct, ct_len,
      tag, GCM_TAG_LEN,
      (uint8_t*)plainBuf
    );
    unsigned long t1 = micros();
    uint32_t heap_after = ESP.getFreeHeap();
    uint32_t heap_min_after = heap_caps_get_minimum_free_size(MALLOC_CAP_8BIT);

    if (!ok_auth) {
      Serial.printf(
        "Recv: enc=2 algorithm=GCM bytes=%u dec_time_us=%lu auth_fail=1 heap_before=%lu heap_after=%lu heap_min=%lu\n",
        length, (unsigned long)(t1 - t0),
        (unsigned long)heap_before, (unsigned long)heap_after, (unsigned long)heap_min_after
      );

      // Publish metadata (auth failure, msg_id unknown)
      publishMetaRx(0, 2, "GCM", length, (t1 - t0), 0, 1,
                    heap_before, heap_after, heap_min_after);

      return;
    }

    plainBuf[ct_len] = '\0';

    uint32_t msg_id = 0;
    bool ok_id = extractMsgId(plainBuf, msg_id);

    bool replay = ok_id && (msg_id <= last_msg_id);
    if (ok_id && !replay) last_msg_id = msg_id;

    Serial.printf(
      "Recv: enc=2 algorithm=GCM bytes=%u dec_time_us=%lu msg_id=%lu replay=%d auth_fail=0 heap_before=%lu heap_after=%lu heap_min=%lu\n",
      length, (unsigned long)(t1 - t0),
      (unsigned long)(ok_id ? msg_id : 0), replay ? 1 : 0,
      (unsigned long)heap_before, (unsigned long)heap_after, (unsigned long)heap_min_after
    );

    // Publish receiver metadata (success)
    publishMetaRx(ok_id ? msg_id : 0, 2, "GCM", length, (t1 - t0), replay ? 1 : 0, 0,
                  heap_before, heap_after, heap_min_after);

    Serial.printf("Plain: %s\n", plainBuf);
    return;
  }

  // ---------------------------------------------------------------------------
  // flag=0: plaintext (supported)
  // Frame: [0][plaintext...]
  // ---------------------------------------------------------------------------
  if (flag == 0) {
    int dataLen = (int)length - 1;
    if (dataLen >= (int)sizeof(plainBuf)) dataLen = sizeof(plainBuf) - 1;

    memcpy(plainBuf, payload + 1, dataLen);
    plainBuf[dataLen] = '\0';

    uint32_t heap_now = ESP.getFreeHeap();
    uint32_t heap_min_now = heap_caps_get_minimum_free_size(MALLOC_CAP_8BIT);

    uint32_t msg_id = 0;
    bool ok = extractMsgId(plainBuf, msg_id);

    bool replay = ok && (msg_id <= last_msg_id);
    if (ok && !replay) last_msg_id = msg_id;

    Serial.printf(
      "Recv: enc=0 algorithm=PLAINTEXT bytes=%u msg_id=%lu replay=%d heap_now=%lu heap_min=%lu\n",
      length, (unsigned long)(ok ? msg_id : 0), replay ? 1 : 0,
      (unsigned long)heap_now, (unsigned long)heap_min_now
    );

    // ADD: publish receiver metadata
    publishMetaRx(ok ? msg_id : 0, 0, "PLAINTEXT", length, 0, replay ? 1 : 0, 0,
                  heap_now, heap_now, heap_min_now);

    Serial.printf("Plain: %s\n", plainBuf);
    return;
  }

  Serial.printf("Recv: drop reason=unknown_flag flag=%u bytes=%u\n", flag, length);
}

static void connectMqtt() {
  while (!mqtt.connected()) {
    Serial.println("Connecting to MQTT...");
    if (mqtt.connect("esp32-receiver")) {
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
  mqtt.setBufferSize(2500);
  mqtt.setKeepAlive(60);

  mqtt.setCallback(onMessage);

  connectMqtt();
}

void loop() {
  if (!mqtt.connected()) connectMqtt();
  mqtt.loop();
}
