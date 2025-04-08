const express = require("express");
const fs = require("fs");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const path = require("path");
const bodyParser = require("body-parser");
const { v4: uuidv4 } = require("uuid");

const app = express();
const PORT = 3000;

// ✅ Your correct Business ID & App ID
const businessId = "5fce6843-6d14-4efe-9a76-88d15d1b2557";
const appId = "urn:aid:712031a5-40a2-43ba-857e-cab85169198a";

// ✅ Use poynt-private-key.pem
const privateKey = fs.readFileSync(path.join(__dirname, "poynt-private-key.pem"));

app.use(bodyParser.json());
app.use(express.static(".")); // Serves HTML

function generateJWT() {
  const now = Math.floor(Date.now() / 1000);
  return jwt.sign({
    iat: now,
    exp: now + 3600,
    iss: appId,
    sub: appId,
    aud: "https://services.poynt.net",
    jti: uuidv4(),
  }, privateKey, { algorithm: "RS256" });
}

async function getAccessToken() {
  const jwtToken = generateJWT();
  const res = await axios.post("https://services.poynt.net/token", new URLSearchParams({
    grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
    assertion: jwtToken,
  }), {
    headers: {
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded",
      "api-version": "1.2",
    },
  });
  return res.data.accessToken;
}

async function chargeNonce(nonce, email, zip) {
  const token = await getAccessToken();

  const payload = {
    action: "SALE",
    context: {
      businessId,
      source: "WEB"
    },
    amounts: {
      transactionAmount: 1999, // $19.99 in cents
      orderAmount: 1999,
      currency: "USD"
    },
    fundingSource: {
      nonce,
      billingContact: {
        address: {
          postalCode: zip
        }
      }
    },
    emailReceipt: true,
    receiptEmailAddress: email
  };

  const res = await axios.post(
    `https://services.poynt.net/businesses/${businessId}/cards/tokenize/charge`,
    payload,
    {
      headers: {
        Authorization: `Bearer ${token}`,
        "Poynt-Request-Id": uuidv4(),
        "Content-Type": "application/json",
      },
    }
  );
  return res.data;
}

app.post("/charge", async (req, res) => {
  const { nonce, email, zip } = req.body;
  try {
    const chargeResult = await chargeNonce(nonce, email, zip);

    // Check approval status
    const isApproved =
      chargeResult.status === "APPROVED" &&
      chargeResult.processorResponse?.status === "Success";

    if (!isApproved) {
      console.warn("⚠️ Charge NOT approved:", chargeResult);
      return res.status(402).json({
        success: false,
        message: `❌ Payment declined: ${chargeResult.processorResponse?.statusMessage || "Unknown reason"}`,
        raw: chargeResult,
      });
    }

    console.log("✅ Payment APPROVED!");
    res.json({
      success: true,
      message: "✅ Payment successful!",
      data: chargeResult,
    });

    // 👉 Here you can safely trigger pass creation
    // await generatePassAndSendEmail(email, petData...);
  } catch (error) {
    console.error("❌ Charge error:", error.response?.data || error.message);
    res.status(500).json({
      success: false,
      message: "❌ Payment failed.",
      error: error.message,
    });
  }
});
app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));
