require('dotenv').config();
const express = require('express');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const bodyParser = require('body-parser');
const stringSimilarity = require('string-similarity');

const app = express();
const port = process.env.PORT || 3000;

const API_KEY = process.env.API_KEY;
const MODEL_ID = process.env.MODEL_ID;
const businessId = process.env.BUSINESS_ID;
const appId = process.env.APP_ID;
const privateKey = fs.readFileSync(path.join(__dirname, "poynt-private-key.pem"));

app.use(cors());
app.use(express.static('public'));
app.use(bodyParser.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

const storage = multer.memoryStorage();
const upload = multer({ storage });

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

function generateBarcode() {
  return Math.random().toString(36).substring(2, 10).toUpperCase();
}

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

async function chargeNonce(nonce, email, zip, additionalHandler) {
  const token = await getAccessToken();
  const totalAmount = additionalHandler === 'on' ? 1999 + 999 : 1999;

  const payload = {
    action: "SALE",
    context: { businessId, source: "WEB" },
    amounts: {
      transactionAmount: totalAmount,
      orderAmount: totalAmount,
      currency: "USD"
    },
    fundingSource: {
      nonce,
      billingContact: { address: { postalCode: zip } }
    },
    emailReceipt: true,
    receiptEmailAddress: String(email)
  };

  const res = await axios.post(
    `https://services.poynt.net/businesses/${businessId}/cards/tokenize/charge`,
    payload,
    {
      headers: {
        Authorization: `Bearer ${token}`,
        "Poynt-Request-Id": uuidv4(),
        "Content-Type": "application/json"
      }
    }
  );

  return res.data;
}

async function uploadPetImage(base64Field) {
  const base64Data = base64Field.replace(/^data:image\/png;base64,/, '');
  const fileName = `uploads/${Date.now()}-cropped.png`;
  fs.writeFileSync(fileName, base64Data, 'base64');
  const imageBuffer = fs.readFileSync(fileName);

  const imageUpload = await axios.post(
    'https://api.pass2u.net/v2/images',
    imageBuffer,
    {
      headers: {
        'Content-Type': 'image/png',
        'Accept': 'application/json',
        'x-api-key': API_KEY,
      }
    }
  );

  fs.unlinkSync(fileName);
  console.log("🧹 Temp image deleted:", fileName);
  return imageUpload.data.hex;
}

async function createPass({ email, handlerName, phone, petName, breed, microchipNumber, registryNumber, barcode, hex, isAdditional }) {
  const payload = {
    barcode: { message: barcode, altText: registryNumber },
    fields: [
      { key: "field3", value: petName },
      { key: "field4", value: registryNumber },
      { key: "field5", value: breed || "N/A" },
      { key: "field10", value: microchipNumber || "N/A" },
      { key: "field6", value: handlerName },
      { key: "field7", value: phone }
    ],
    images: [{ type: "thumbnail", hex }]
  };

  const passRes = await axios.post(
    `https://api.pass2u.net/v2/models/${MODEL_ID}/passes`,
    payload,
    {
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'x-api-key': API_KEY
      }
    }
  );

  const passUrl = `https://www.pass2u.net/d/${passRes.data.passId}`;
  console.log(`✅ ${isAdditional ? 'Additional' : 'Main'} pass created:`, passUrl);

  await transporter.sendMail({
    from: `"Pawthorized" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: isAdditional ? "Service Animal ID for Additional Handler" : "Your Service Animal Wallet ID",
    html: `
      <h3>Your ${isAdditional ? 'Additional Handler' : 'Service Animal'} Digital ID is Ready</h3>
      <p>You can now add it to your phone wallet:</p>
      <a href="${passUrl}" style="padding: 10px 20px; background: #004aad; color: white; text-decoration: none; border-radius: 5px;">Add to Wallet</a>
    `
  });

  return passUrl;
}

// ✅ Final /charge with fuzzy approval logic
app.post("/charge", upload.none(), async (req, res) => {
  try {
    const {
      petImageBase64, petName, breed, registryNumber, microchipNumber,
      handlerName, phone, email,
      additionalHandler, additionalHandlerName, additionalEmail,
      nonce, zip
    } = req.body;

    if (!petName || !petImageBase64 || !handlerName || !phone || !email) {
      return res.status(400).json({ success: false, message: "❌ Missing required fields." });
    }
    if (additionalHandler === "on" && (!additionalHandlerName || !additionalEmail)) {
      return res.status(400).json({ success: false, message: "❌ Missing additional handler info." });
    }

    const chargeResult = await chargeNonce(nonce, email, zip, additionalHandler);
    console.log("💳 Payment result:", chargeResult);

    const APPROVED_MESSAGES = [
      "success", "successful", "successfully", "succeeded",
      "approved", "approval", "approve",
      "complete", "completed",
      "ok", "okay",
      "authorized", "authorised", "authorization", "authorisation",
      "transaction approved", "transaction successful", "successfully processed",
      "purchase approved", "accepted", "confirmed", "done", "valid", "validated",
      "charged", "processed", "settled"
    ];
    const APPROVED_CODES = [
      "00", "08", "10", "11", "85", "86", "87", "A1", "Y1", "Z3", "000", "100", "200", "300", "05"
    ];
    const normalizeText = (text) => {
      if (!text) return '';
      return text.toLowerCase().replace(/[^a-z0-9\s]/g, '').replace(/\s+/g, ' ').trim();
    };

    const rawStatus = normalizeText(chargeResult.status || chargeResult.processorResponse?.status || '');
    const rawCode = normalizeText(chargeResult.processorResponse?.responseCode || chargeResult.processorResponse?.code || '');
    const statusMessage = normalizeText(chargeResult.processorResponse?.statusMessage || chargeResult.processorResponse?.message || '');

    const isMessageApproved = () => {
      if (APPROVED_MESSAGES.includes(rawStatus) || APPROVED_MESSAGES.includes(statusMessage)) {
        return true;
      }
      for (const msg of APPROVED_MESSAGES) {
        const sim1 = stringSimilarity.compareTwoStrings(rawStatus, msg);
        const sim2 = stringSimilarity.compareTwoStrings(statusMessage, msg);
        if (sim1 > 0.85 || sim2 > 0.85) {
          console.log(`🔍 Fuzzy matched "${rawStatus}" or "${statusMessage}" ≈ "${msg}"`);
          return true;
        }
      }
      return false;
    };

    const isCodeApproved = () =>
      APPROVED_CODES.includes(rawCode) || /^[0-3]{1,3}$/.test(rawCode);

    if (!isMessageApproved() && !isCodeApproved()) {
      console.warn("⚠️ Unrecognized payment status:", { rawStatus, rawCode, statusMessage });
      return res.status(402).json({ success: false, message: "❌ Payment declined: " + (statusMessage || "Unknown") });
    }

    const hex = await uploadPetImage(petImageBase64);
    const barcode = registryNumber || "CSA-" + generateBarcode();
    const passUrl = await createPass({
      email,
      handlerName,
      phone,
      petName,
      breed,
      microchipNumber,
      registryNumber: barcode,
      barcode,
      hex
    });

    if (additionalHandler === "on") {
      const extraBarcode = barcode + "-A";
      await createPass({
        email: additionalEmail,
        handlerName: additionalHandlerName,
        phone,
        petName,
        breed,
        microchipNumber,
        registryNumber: barcode,
        barcode: extraBarcode,
        hex,
        isAdditional: true
      });
    }

    res.json({ success: true, redirectUrl: "/success.html" });

  } catch (err) {
    console.error("❌ Charge or pass creation failed:", err.response?.data || err.message);
    res.status(500).json({ success: false, message: "❌ Payment or pass generation failed." });
  }
});
// ✅ Endpoint for dynamic price based on handler selection
app.post('/get-amount', (req, res) => {
    const { additionalHandler } = req.body;
    const totalAmount = additionalHandler === 'on' ? 1999 + 999 : 1999;
    const amountInDollars = (totalAmount / 100).toFixed(2);
    res.json({ amount: amountInDollars });
  });
app.listen(port, () => {
  console.log(`🚀 Server running at http://localhost:${port}`);
});
