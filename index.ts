// Environment required
if (!process.env.SERVER_DID || !process.env.SERVER_PRIVATE_KEY) {
  throw new Error("Faltan las variables de entorno SERVER_DID y SERVER_PRIVATE_KEY")
}

const didData = require('./did.json')
const express = require('express')
const bodyParser = require('body-parser')
const ngrok = require('ngrok')
const decodeJWT = require('did-jwt').decodeJWT
const { Credentials } = require('uport-credentials')
const transports = require('uport-transports').transport
const message = require('uport-transports').message.util
const randomstring = require('randomstring')

const { success, fail, error } = require('./Utils')

const nunjucks = require('nunjucks');

import { Resolver } from 'did-resolver'
import { getResolver } from 'ethr-did-resolver'

import { verifyCredential } from 'did-jwt-vc'
import { truncateSync } from 'fs'
import { NPN_ENABLED } from 'constants'

const app = express();

nunjucks.configure("public",{autoescape:true, express: app})
const resolver = new Resolver(getResolver())


let endpoint = null
let port = process.env.PORT ? parseInt(process.env.PORT, 10) : 8090

app.use(bodyParser.json({ type: '*/*' }))
//setup Credentials object with newly created application identity.

let codes = []
const credentials = new Credentials({
  appName: 'Request Verification Example',
  did: process.env.SERVER_DID,
  privateKey: process.env.SERVER_PRIVATE_KEY
})

app.use("/", express.static(__dirname + '/public'));
app.get('/api/disclosure', (req, res) => {
  let url = endpoint !== null ? endpoint : 'http://' + req.hostname  + ':' + port
  let code = randomstring.generate();
  console.log(Date.now())
  credentials.createDisclosureRequest({
    verified: ['didiserver'],
    exp: Math.floor(Date.now()/1000) + (60*60*24*365),
    callbackUrl: url + '/api/callback/' + code

  }).then(requestToken => {
    console.log(decodeJWT(requestToken))  //log request token to console
    const uri = message.paramsToQueryString(message.messageToURI(requestToken), {callback_type: 'post'})
    const qr =  transports.ui.getImageDataURI(uri)
    codes.push({ code, status: false })
    success(res, { code, qr, requestToken })
  }).catch(e => {
    console.error(e)
    error(res, 'Error interno')
  })
})

app.get('/api/check/:code', (req, res) => {
  let value = codes.find(c => c.code === req.params.code)
  let reply = {
    status: value ? value.status : false,
    jwt: value ? value.jwt : ''
  }
  success(res, reply)
})

app.get('/api/credential_viewer/:token',(req,res) => {
  const jwt = req.params.token
  verifyCredential(jwt, resolver).then(function(verifiedVC) {
    const data= verifiedVC.payload.vc.credentialSubject
    const issuer = verifiedVC.payload.iss
    var nombre = didData.filter(it => it.did === issuer)
    var name:String=""
    if ( nombre.length==0 ) {name= issuer + " (emisor desconocido)"} else {name= nombre[0].name}
    res.render("viewer.html",{iss: name, credential: data, error: false})
  }).catch(function(err) {
    console.log(err)
    res.render("viewer.html",{iss: false ,credential: false ,error: err})
  })
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
    success(res, true)
  }).catch( err => {
    console.log(err)
    error(res, 'Error interno')
  })
})

app.post('/api/verify', (req, res) => {
  let jwt = req.body.jwt

  verifyCredential(jwt, resolver).then(function(verifiedVC) {
    var credential = verifiedVC.payload.vc.credentialSubject
    console.log(credential)
    success(res,credential)
})

  //TODO verificar jwt
/*   try {
    let decode = decodeJWT(jwt)
    console.log(decode)
    let verified = decode.payload.verified[0]

    if (!verified) {
      return fail(res, 'No existe atributo verified')
    }

    let credential = decodeJWT(verified)

    success(res, jwt)
  } catch(e) {
    console.error('error', e)
    error(res, e.message)
  }  */ 
})
/*
app.get('/api/credential/:code', (req, res) => {
  const code = req.params.code
  let data = codes.find(c => c.code === code)

  if (!data) {
    return fail(res, 'El codigo no existe')
  }

  let decode = decodeJWT(data.jwt)
  console.log('[decode]', decode)
  //TODO falta la validacion del issuer
  if (decode.payload.aud !== process.env.TMP_DID) {
    return fail(res, 'El issuer no es valido')
  }

  let reply = {
    //didiserver: decode.payload.own.didiserver,
    didiserver: decode.payload.own.didiserver,
    iss: decode.payload.aud
  }
  success(res, reply)
})*/


// run the app server and tunneling service
app.listen(port, () => {
  if (process.env.DISABLE_NGROK) {
    console.log('Verification Service running, no NGROK', port)
  } else {
    ngrok.connect(port).then(ngrokUrl => {
      endpoint = ngrokUrl
      console.log(`Verification Service running, open at ${ngrokUrl}`)
    })
  }
})
