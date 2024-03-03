//import statements
const express = require('express');
const NodeRSA = require('node-rsa');
const uuid = require('uuid');
const jwt = require('jsonwebtoken');
//express instance
const app = express();
//specify port
const port = 8080;

//init empty array to hold keys
let keys = [];

//function to generate rsa keys
const generateKeyPair = () => {
  //generate key and export to public/private
  const key = new NodeRSA({ b: 2048 });
  const publicKey = key.exportKey('public');
  const privateKey = key.exportKey('private');
  //generate random kid from uuid lib
  const kid = uuid.v4();
  //set expiry date to current date + 1 hour (60minx60sec=3600)
  const expiry = Math.floor(Date.now() / 1000) + 3600; // 1 hour expiration
  //return keys, kid, expirey
  return { publicKey, privateKey, kid, expiry };
};

//call generatekeys and store result in array
keys.push(generateKeyPair());

// Endpoint to generate JWT
app.post('/auth', (req, res) => {
  //extract kid
  const kid = keys[0].kid;
  //log kid
  console.log('Generating JWT for kid:', kid);
  //generate jwt from kid
  const JWT = generateAccessToken(kid);
  res.json({ JWT });
});

// Function to generate JWT
function generateAccessToken(kid) {
  //current date
  const now = Math.floor(Date.now() / 1000);

  //filter out expire dkeys
  const validKeys = keys.filter((key) => key.expiry > now);

  //if key is expired, return null
  if (!validKeys.length) {
    return null; // No valid keys available
  }
  //store valid keys
  const validKey = validKeys[0];

  // Sign JWT with the private key
  const token = jwt.sign({}, validKey.privateKey, {
    expiresIn: validKey.expiry - now,
    algorithm: 'RS256',
    keyid: kid,
  });
  //return token
  return token;
}

// Endpoint to provide JWKS
app.get('/.well-known/jwks.json', (req, res) => {
  const JWK = {
    keys: keys.map((key) => ({
      kid: key.kid,
      kty: 'RSA',
      use: 'sig',
      alg: 'RS256',
      n: key.publicKey.split('-----')[2].replace(/\n/g, ''),
      e: 'AQAB',
    })),
  };
  //return jwk
  res.status(200).json(JWK);
});

// Endpoint to retrieve a specific JWK based on kid
app.get('/.well-known/:kid.json', (req, res) => {
  const requestedKid = req.params.kid;
  console.log('Requested JWK for kid:', requestedKid);
  const requestedKey = keys.find((key) => key.kid === requestedKid);

  if (requestedKey) {
    const JWK = {
      kid: requestedKey.kid,
      kty: 'RSA',
      use: 'sig',
      alg: 'RS256',
      n: requestedKey.publicKey.split('-----')[2].replace(/\n/g, ''),
      e: 'AQAB',
    };

    res.status(200).json(JWK);
  } else {
    res.status(404).json({ error: 'Key Not Found' });
  }
});

// Handle other requests with a 405 status code
app.use((req, res) => {
  res.status(405).json({ error: 'Method Not Allowed' });
});

//start server and log port
app.listen(port, () => {
  console.log(`App listening on port ${port}`);
});
