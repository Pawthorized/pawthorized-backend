const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");
const axios = require("axios");

const businessId = "5fce6843-6d14-4efe-9a76-88d15d1b2557";
const appId = "urn:aid:712031a5-40a2-43ba-857e-cab85169198a";

const privateKey = fs.readFileSync(path.join(__dirname, "poynt-private-key.pem"), "utf8");

const now = Math.floor(Date.now() / 1000);
const payload = {
  iss: appId,
  sub: appId,
  aud: "https://services.poynt.net",
  iat: now,
  exp: now + 60 * 60,
  jti: Math.random().toString(36).substring(2) + now,
};

const token = jwt.sign(payload, privateKey, {
  algorithm: "RS256",
});

console.log("🔐 JWT Created. Requesting access token...");

axios
  .post("https://services.poynt.net/token", new URLSearchParams({
    grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
    assertion: token,
  }), {
    headers: {
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded",
      "api-version": "1.2",
    },
  })
  .then((res) => {
    console.log("✅ Access Token:", res.data.accessToken);
  })
  .catch((err) => {
    console.error("❌ Error getting token:", err.response?.data || err.message);
  });
