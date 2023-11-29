import express from "express";
import {SecureManager} from './secure.js'
// import forgeBundle from 'Library/forgeBunedle.js'
import nodeForge from 'forge'
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
// app.use(nodeForge)

app.post("/generate-pin", (req, res) => {
  var publicKeyModulus =
    "009c7b3ba621a26c4b02f48cfc07ef6ee0aed8e12b4bd11c5cc0abf80d5206be69e1891e60fc88e2d565e2fabe4d0cf630e318a6c721c3ded718d0c530cdf050387ad0a30a336899bbda877d0ec7c7c3ffe693988bfae0ffbab71b25468c7814924f022cb5fda36e0d2c30a7161fa1c6fb5fbd7d05adbef7e68d48f8b6c5f511827c4b1c5ed15b6f20555affc4d0857ef7ab2b5c18ba22bea5d3a79bd1834badb5878d8c7a4b19da20c1f62340b1f7fbf01d2f2e97c9714a9df376ac0ea58072b2b77aeb7872b54a89667519de44d0fc73540beeaec4cb778a45eebfbefe2d817a8a8319b2bc6d9fa714f5289ec7c0dbc43496d71cf2a642cb679b0fc4072fd2cf";
  var publicKeyExponent = "010001";
  var key = SecureManager.generateKey();
  const card = req.body.formCard
  const cvv2 = req.body.formCvv2
  const pin = req.body.formPin
  const exp = req.body.exp  
  var optionObj = {
    pan: card,
    publicKeyModulus: publicKeyModulus,
    publicKeyExponent: publicKeyExponent,
    pinKey: key,
  };

  var secureData = SecureManager.getSecureVersion10(optionObj);
  var pinData = SecureManager.getPinBlock(pin, exp, key, cvv2);

  //alert("pin data - "+ pinData + "\n" + "secureData - " + secureData);
//   $("#form-secure").val(secureData);
//   $("#form-pindata").val(pinData);   
// res.json({secureData,pinData})
  console.log(secureData)
});

app.listen(5000, () => console.log('connect'));
