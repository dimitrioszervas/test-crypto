import React from 'react';

// Helper function to encode text to Uint8Array
const encodeText = (text) => new TextEncoder().encode(text);

// Function to import a secret key for HKDF
const importSecretKey = async (secretText) => {
  return window.crypto.subtle.importKey(
    'raw',
    encodeText(secretText),
    { name: 'HKDF' },
    false,
    ['deriveKey', 'deriveBits']
  );
};

// Function to derive bits using HKDF
const deriveBitsHKDF = async (secretKey, saltText, infoText, bits) => {
  return window.crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: encodeText(saltText),
      info: encodeText(infoText),
    },
    secretKey,
    bits
  );
};

// Function to generate n keys of a specific type (sign or encrypt)
const generateNKeys = async (n, salt, type, baseKey) => {
  try {
    const derivedKeyAlgo = type === "sign" ? 
      { name: "HMAC", hash: "SHA-256", length: 256 } : 
      { name: "AES-GCM", length: 256 };
    const keyUsage = type === "sign" ? ["sign", "verify"] : ["encrypt", "decrypt"];
    const info = encodeText(type === "sign" ? "signs" : "encrypts");
    let keys = [];

    for (let i = 0; i <= n; i++) {
      const key = await window.crypto.subtle.deriveKey(
        { name: "HKDF", hash: "SHA-256", salt, info },
        baseKey,
        derivedKeyAlgo,
        true,
        keyUsage
      );
      keys.push(key);
    }
    return keys;
  } catch (error) {
    console.error(`Error in generateNKeys for ${type}:`, error.message);
    throw error;
  }
};

const generateKeys = async(secretString, n) => {
  try {
    const saltString = "";
    const secret = await importSecretKey(secretString);

    // Deriving bits for src, sign, and encrypt
    const srcAB = await deriveBitsHKDF(secret, saltString, "src", 64);
    const signAB = await deriveBitsHKDF(secret, saltString, "sign", 256);
    const encryptAB = await deriveBitsHKDF(secret, saltString, "encrypt", 256);

    const sign = await importSecretKey(new Uint8Array(signAB));
    const encrypt = await importSecretKey(new Uint8Array(encryptAB));
   
    const encrypts = await generateNKeys(n, srcAB, "encrypt", encrypt);
    const signs = await generateNKeys(n, srcAB, "sign", sign);

    const src = new Uint8Array(srcAB);

    return [encrypts, signs, src];

  } catch (error) {
    console.error("Error in generateKeys:", error.message);
    throw error;
  }
}
function App() {
  async function handleClick() {
    
    const n = 3;
    let [encrypts, signs, src] = await generateKeys("secret", n);

    // Example of how to use the generated keys
    console.log("Generated keys:");
    encrypts.forEach((key, i) => console.log(`encrypt[${i}]:`, key));
    signs.forEach((key, i) => console.log(`sign[${i}]:`, key));
  }

  return (
    <div>
      <button onClick={handleClick} style={{
        textAlign: 'center',
        width: '100px',
        border: '1px solid gray',
        borderRadius: '5px',
        padding: '10px',
        cursor: 'pointer',
        marginTop: '20px'
      }}>
        Send data to backend
      </button>
    </div>
  );
}

export default App;