const express = require('express')
const bodyParser = require('body-parser')
const ngrok = require('ngrok')
const decodeJWT = require('did-jwt').decodeJWT
const { Credentials } = require('uport-credentials')
const transports = require('uport-transports').transport
const message = require('uport-transports').message.util
const randomstring = require('randomstring')

const { success, fail, error } = require('./Utils')

const app = express();

let endpoint = ''
app.use(bodyParser.json({ type: '*/*' }))
//setup Credentials object with newly created application identity.

let codes = []
const credentials = new Credentials({
  appName: 'Request Verification Example',
  did: 'did:ethr:0x31486054a6ad2c0b685cd89ce0ba018e210d504e',
  privateKey: 'ef6a01d0d98ba08bd23ee8b0c650076c65d629560940de9935d0f46f00679e01'
})

app.use("/", express.static(__dirname + '/public'));
app.get('/api/disclosure', (req, res) => {
  let code = randomstring.generate();
  credentials.createDisclosureRequest({
    verified: ['didiserver'],
    callbackUrl: endpoint + '/api/callback/' + code
  }).then(requestToken => {
    console.log(decodeJWT(requestToken))  //log request token to console
    const uri = message.paramsToQueryString(message.messageToURI(requestToken), {callback_type: 'post'})
    const qr =  transports.ui.getImageDataURI(uri)
    codes.push({ code, status: false })
    success(res, { code, qr })
  }).catch(e => {
    console.error(e)
    error(res, 'Error interno')
  })
})

app.get('/api/check/:code', (req, res) => {
  let value = codes.find(c => c.code === req.params.code)
  success(res, value ? value.status : false)
})

app.post('/api/callback/:code', (req, res) => {
  const code = req.params.code
  const jwt = req.body.access_token
  console.log('[JWT]', jwt)
  console.log('[JWT decode]', decodeJWT(jwt))
  credentials.authenticateDisclosureResponse(jwt).then(creds => {
    //validate specific data per use case
    console.log('[credencial]', creds)
    //console.log(creds.verified[0])
    codes = [...codes.filter(c => c.code !== code), { code, jwt, status: true }]
    success(res, creds)
  }).catch( err => {
    console.log(err)
    error(res, 'Error interno')
  })
})

app.get('/api/credential/:code', (req, res) => {
  const code = req.params.code
  let data = codes.find(c => c.code === code)

  if (!data) {
    return fail(res, 'El codigo no existe')
  }

  let decode = decodeJWT(data.jwt)
  if (decode.payload.iss !== 'did:ethr:0x4a65a357b27c736f9493b761431f5afcc053e332') {
    return fail(res, 'El issuer no es valido')
  }

  let reply = {
    didiserver: decode.payload.own.didiserver,
    //didiserver: decode.payload.vc.credentialSubject.didiserver,
    iss: decode.payload.iss
  }
  success(res, reply)
})


// run the app server and tunneling service
app.listen(8088, () => ngrok.connect(8088).then(ngrokUrl => {
  endpoint = ngrokUrl
  console.log(`Verification Service running, open at ${endpoint}`)
}))