import './App.css';

// fucntion to generate n keys.
const generateNKeys = async (n, salt, type, baseKey) => {

  try {
    
    let derivedKeyAlgo, keyUsage, info;
    if (type === "sign") {
      // if we want to create keys which will be used to sign the data
      derivedKeyAlgo = { name: "HMAC", hash: "SHA-256", length: 256 };
      keyUsage = ["sign", "verify"];    
      info = new TextEncoder().encode("signs");
    } else {
      derivedKeyAlgo = { name: "AES-GCM", length: 256 };
      keyUsage = ["encrypt", "decrypt"];     
      info = new TextEncoder().encode("encrypts");
    }
    let keys = []; // array to store n keys

    // for loop to generate n keys
    for (let i = 0; i <= n; i++) {
      // here we are creating a key using HKDF algorithm
      const key = await window.crypto.subtle.deriveKey(
        {
          name: "HKDF",
          hash: "SHA-256",
          salt: salt,
          info: info
        },
        baseKey,
        derivedKeyAlgo,
        true,
        keyUsage
      );
      keys.push(key);
    }
    return keys;
  } catch (error) {
    console.error("Error in generateNKeys:", error.message);
    throw error;
  }
};

const generateKeys = async(secretText, n) => {
  try {
    const secretString = secretText;
    let saltString  = "";

    console.log("secret string: ", secretString);
    
    let secretRaw = new TextEncoder().encode(secretString);
    let salt = new TextEncoder().encode(saltString);

    console.log("secret: ", secretRaw);

    // generateKey cannot be used to create a key which will be used to drive other keys in future so using importKey function
    let secret = await window.crypto.subtle.importKey("raw", secretRaw, "HKDF", false, [
      "deriveBits",
      "deriveKey",
    ]);
    console.log("secret or baseKey: ", secret);
  
      // creating SRC from the SECRET
    let srcAB = await window.crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: salt,
        info: new TextEncoder().encode("src"),
      },
      secret,
      64
    );

    let src = new Uint8Array(srcAB);

    salt = src;

    console.log("src: ", src);

    // Derive sign Key from secret
    let signAB = await window.crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: salt,
        info: new TextEncoder().encode("sign"),
      },
      secret,      
      256
    );     

    let signRaw = new Uint8Array(signAB);

    console.log("sign: ", signRaw);

    let sign = await window.crypto.subtle.importKey("raw", signAB, "HKDF", false, [
      "deriveKey",
    ]);

    // Derive encrypt Key from secret
    let encryptAB = await window.crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: salt,
        info: new TextEncoder().encode("encrypt"),
      },
      secret,      
      256
    );     

    let encryptRaw = new Uint8Array(encryptAB);

    console.log("encrypt: ", encryptRaw);

    let encrypt = await window.crypto.subtle.importKey("raw", encryptAB, "HKDF", false, [  
      "deriveKey",
    ]);
      
    const encrypts = await generateNKeys(n, salt, "encrypt", encrypt);      
    const signs = await generateNKeys(n, salt, "sign", sign);  
 
    return [encrypts, signs, src];

  } catch (error) {
    console.error("Error in generateKeys:", error.message);
    throw error;
  }
}

function App() {
  
  async function handleClick() {
   
    // Function to encrypt a shard with a given CryptoKey
    async function encryptShard(shard, cryptoKey, srcIn) {
      
      let iv = new Uint8Array(12);     
      for (let i = 0; i < srcIn.length; i++) {
        iv[i] = srcIn[i].length;
      }
      const algo = { name: "AES-GCM", iv: iv, tagLength: 128 };
      const ciphertext = await crypto.subtle.encrypt(algo, cryptoKey, shard);
      return new Uint8Array(ciphertext);
    }

    // Function to decrypt a shard with a given CryptoKey
    async function decryptShard(encrypted, cryptoKey, srcIn) {
      
      let iv = new Uint8Array(12);
      for (let i = 0; i < srcIn.length; i++) {
        iv[i] = srcIn[i].length;
      }
      const algo = { name: "AES-GCM", iv: iv, tagLength: 128 };
      const plaintext = await crypto.subtle.decrypt(algo, cryptoKey, encrypted);
      return new Uint8Array(plaintext);
    }
    

    const n = 3;
    let [encrypts, signs, src] = await generateKeys("secret", n);
    
    console.log("encrypts: ");
    for (let i=0; i < encrypts.length; i++) {
      let raw = new Uint8Array(await window.crypto.subtle.exportKey("raw", encrypts[i]));
      console.log("encrypt[", i, "]: ", raw);
    }

    console.log("signs: ");
    for (let i=0; i < signs.length; i++) {
      let raw = new Uint8Array(await window.crypto.subtle.exportKey("raw", signs[i]));
      console.log("sign[", i, "]: ", raw);
    }

    let data = "Test Ecryption";
    let dataBytes = new TextEncoder().encode(data);

    console.log("Data bytes: ", dataBytes);

    let encryptedShard = await encryptShard(dataBytes, encrypts[1], src);

    console.log("Encrypted bytes: ", encryptedShard);

    let decryptedShard = await decryptShard(encryptedShard, encrypts[1], src);

    console.log("Decrypted bytes: ", decryptedShard);
  }

  return (
    <div onClick={handleClick} style={{
      textAlign: 'center',
      width: '100px',
      border: '1px solid gray',
      borderRadius: '5px'
    }}>
      Run Test
    </div>
  );
}

export default App;
