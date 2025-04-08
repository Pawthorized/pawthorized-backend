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
const port = 3000;

const API_KEY = 'a94f43b7721964ce4e393870e5b15044';
const MODEL_ID = '310361';
const businessId = "5fce6843-6d14-4efe-9a76-88d15d1b2557";
const appId = "urn:aid:712031a5-40a2-43ba-857e-cab85169198a";
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
        user: 'pawthorized@gmail.com',
        pass: 'kcyyfixzooqzlnlg'
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
        from: '"Pawthorized" <pawthorized@gmail.com>',
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

// ✅ /charge route
app.post("/charge", async (req, res) => {
    const { nonce, email, zip, additionalHandler } = req.body;

    try {
        const chargeResult = await chargeNonce(nonce, email, zip, additionalHandler);

        const isApproved =
            chargeResult.status === "APPROVED" &&
            chargeResult.processorResponse?.status === "Success";

        if (!isApproved) {
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

// ✅ /create-pass route
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

app.listen(port, () => {
    console.log(`🚀 Server running at http://localhost:${port}`);
});
