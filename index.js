const express = require('express')
const bodyParser = require('body-parser')
const ngrok = require('ngrok')
const decodeJWT = require('did-jwt').decodeJWT
const { Credentials } = require('uport-credentials')
const transports = require('uport-transports').transport
const message = require('uport-transports').message.util

let endpoint = ''
const app = express();
app.use(bodyParser.json({ type: '*/*' }))

//setup Credentials object with newly created application identity.
const credentials = new Credentials({
  appName: 'Request Verification Example',
  did: 'did:ethr:0x31486054a6ad2c0b685cd89ce0ba018e210d504e',
  privateKey: 'ef6a01d0d98ba08bd23ee8b0c650076c65d629560940de9935d0f46f00679e01'
})

app.get('/', (req, res) => {
    credentials.createDisclosureRequest({
      verified: ['didicertificate'],
      callbackUrl: endpoint + '/callback'
    }).then(requestToken => {
      console.log(decodeJWT(requestToken))  //log request token to console
      const uri = message.paramsToQueryString(message.messageToURI(requestToken), {callback_type: 'post'})
      const qr =  transports.ui.getImageDataURI(uri)
      res.send(`<div><img src="${qr}"/></div>`)
    })
  })


app.post('/callback', (req, res) => {
    const jwt = req.body.access_token
    console.log(jwt)
    console.log(decodeJWT(jwt))
    credentials.authenticateDisclosureResponse(jwt).then(creds => {
      //validate specific data per use case
      console.log(creds)
      console.log(creds.verified[0])
    }).catch( err => {
      console.log(err)
    })
  })
  


// run the app server and tunneling service
const server = app.listen(8088, () => {
    ngrok.connect(8088).then(ngrokUrl => {
      endpoint = ngrokUrl
      console.log(`Verification Service running, open at ${endpoint}`)
    })
  })