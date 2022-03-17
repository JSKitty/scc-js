var signatureUtils = require('./scripts/sign.js')


var message = 'test'
const messagemagic = "\x19DarkCoin Signed Message:\n";
const privateKey = "eZJbJgGXGTY4K9ktbPCAw7N8jdSrrQCoaxwhh1wzFDT8BsHwjipJ"

//It is highly recomended to use extraEntropy when not testing. This makes R value reuse not an issue!
signatureUtils.sign(message, privateKey, true, messagemagic, {extraEntropy:true} ).then(function(results){
    console.log("signature")
    console.log(results.toString('base64'))
})


//For testing only!
// signatureUtils.sign(message, privateKey, true, messagemagic).then(function(results){
//     console.log("signature")
//     console.log(results.toString('base64'))
// })
