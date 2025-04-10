require('dotenv').config();
const express = require('express');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');

const app = express();
const port = process.env.PORT || 3000;


// 🔐 Secure values from environment variables
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
        context: {
            businessId,
            source: "WEB"
        },
        amounts: {
            transactionAmount: totalAmount,
            orderAmount: totalAmount,
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

function generateBarcode() {
    return Math.random().toString(36).substring(2, 10).toUpperCase();
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

    return imageUpload.data.hex;
}

async function createAndSendPass({ email, handlerName, phone, petName, breed, microchipNumber, registryNumber, hex }) {
    const barcode = generateBarcode();
    const payload = {
        barcode: { message: barcode, altText: barcode },
        fields: [
            { key: "field3", value: petName },
            { key: "field4", value: registryNumber || "CSA-" + barcode },
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

    await transporter.sendMail({
        from: '"Pawthorized" <' + process.env.EMAIL_USER + '>',
        to: email,
        subject: "Your Service Animal Wallet ID",
        html: `
            <h3>Your Service Animal Digital ID is Ready</h3>
            <p>You can now add it to your phone wallet:</p>
            <a href="${passUrl}" style="padding: 10px 20px; background: #004aad; color: white; text-decoration: none; border-radius: 5px;">Add to Wallet</a>
        `
    });

    return passUrl;
}
// New endpoint to get the amount dynamically
app.post("/get-amount", (req, res) => {
    const { additionalHandler } = req.body;
    const totalAmount = additionalHandler === 'on' ? 1999 + 999 : 1999;
    const amountInDollars = (totalAmount / 100).toFixed(2);
    res.json({ amount: amountInDollars }); // e.g., "19.99" or "29.98"
  });
  
// ✅ Updated /charge route with smarter approval detection
app.post("/charge", async (req, res) => {
    const { nonce, email, zip, additionalHandler } = req.body;
  
    try {
      const chargeResult = await chargeNonce(nonce, email, zip, additionalHandler);
  
      // Normalize values from processor
const APPROVED_MESSAGES = [
    "success",
    "successfull",
    "approved",
    "approval",
    "complete",
    "completed",
    "ok",
    "authorized",
    "authorization",
    "transaction approved",
    "transaction successful",
    "successfully processed",
    "purchase approved",
    "accepted"
  ];
  
  const APPROVED_CODES = [
    "00", "08", "11", "85", "86", "87", "A1", "Y1", "Z3"
  ];
  
      const rawStatus = (chargeResult.processorResponse?.status || "").toLowerCase().replace(/[^a-z]/g, "").trim();
      const rawCode = (chargeResult.processorResponse?.responseCode || "").trim();
  
      const isApproved =
        chargeResult.status === "APPROVED" &&
        (APPROVED_MESSAGES.includes(rawStatus) || APPROVED_CODES.includes(rawCode));
  
      if (!isApproved) {
        console.warn("⚠️ Unrecognized processor response:", chargeResult.processorResponse);
        return res.status(402).json({
          success: false,
          message: "❌ Payment declined: " + (chargeResult.processorResponse?.statusMessage || "Unknown"),
          raw: chargeResult
        });
      }
  
      res.json({ success: true, message: "✅ Payment successful!" });
    } catch (err) {
      console.error("❌ Charge error:", err.response?.data || err.message);
      res.status(500).json({ success: false, message: "❌ Payment failed.", error: err.message });
    }
  });
  

app.post('/create-pass', upload.none(), async (req, res) => {
    try {
        const {
            petImageBase64,
            petName,
            registryNumber,
            breed,
            microchipNumber,
            handlerName,
            phone,
            email,
            additionalHandler,
            additionalHandlerName,
            additionalEmail
        } = req.body;

        if (!petImageBase64) throw new Error("Missing pet image");

        const hex = await uploadPetImage(petImageBase64);

        await createAndSendPass({
            email,
            handlerName,
            phone,
            petName,
            breed,
            microchipNumber,
            registryNumber,
            hex
        });

        if (additionalHandler === "on" && additionalEmail && additionalHandlerName) {
            await createAndSendPass({
                email: additionalEmail,
                handlerName: additionalHandlerName,
                phone,
                petName,
                breed,
                microchipNumber,
                registryNumber,
                hex
            });
        }

        res.redirect(`/success.html`);
    } catch (error) {
        console.error('❌ Error creating pass:', error.response?.data || error.message);
        res.status(500).send("❌ Something went wrong.");
    }
});

app.get("/.well-known/apple-developer-merchantid-domain-association", async (req, res) => {
    try {
      const token = await getAccessToken();
      const result = await axios.get(
        `https://services.poynt.net/businesses/${process.env.BUSINESS_ID}/apple-pay/domain-association-file`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "text/plain"
          }
        }
      );
      res.setHeader("Content-Type", "text/plain");
      res.send(result.data);
    } catch (err) {
      console.error("❌ Error fetching Apple Pay domain-association-file:", err.message);
      res.status(500).send("Failed to fetch Apple Pay domain association file");
    }
  });
  
  
  app.all("/register-apple-pay", async (req, res) => {
    try {
      const token = await getAccessToken();
      const response = await axios.post(
        `https://services.poynt.net/businesses/${process.env.BUSINESS_ID}/apple-pay/registration`,
        {
          registerDomains: ["pawthorized.com"],
          merchantName: "Pawthorized",
          merchantUrl: "https://pawthorized.com"
        },
        {
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json"
          }
        }
      );
      res.json(response.data);
    } catch (err) {
      console.error("❌ Apple Pay registration failed:", err.response?.data || err.message);
      res.status(500).json({ error: "Apple Pay registration failed" });
    }
  });
  
app.listen(port, () => {
    console.log(`🚀 Server running at http://localhost:${port}`);
});
