"use strict";
var __spreadArrays = (this && this.__spreadArrays) || function () {
    for (var s = 0, i = 0, il = arguments.length; i < il; i++) s += arguments[i].length;
    for (var r = Array(s), k = 0, i = 0; i < il; i++)
        for (var a = arguments[i], j = 0, jl = a.length; j < jl; j++, k++)
            r[k] = a[j];
    return r;
};
exports.__esModule = true;
// Environment required
if (!process.env.SERVER_DID || !process.env.SERVER_PRIVATE_KEY) {
    throw new Error("Faltan las variables de entorno SERVER_DID y SERVER_PRIVATE_KEY");
}
var didData = require('./did.json');
var express = require('express');
var bodyParser = require('body-parser');
var ngrok = require('ngrok');
var decodeJWT = require('did-jwt').decodeJWT;
var Credentials = require('uport-credentials').Credentials;
var transports = require('uport-transports').transport;
var message = require('uport-transports').message.util;
var randomstring = require('randomstring');
var _a = require('./Utils'), success = _a.success, fail = _a.fail, error = _a.error;
var nunjucks = require('nunjucks');
var did_resolver_1 = require("did-resolver");
var ethr_did_resolver_1 = require("ethr-did-resolver");
var did_jwt_vc_1 = require("did-jwt-vc");
var app = express();
nunjucks.configure("public", { autoescape: true, express: app });
var resolver = new did_resolver_1.Resolver(ethr_did_resolver_1.getResolver());
var endpoint = null;
var port = process.env.PORT ? parseInt(process.env.PORT, 10) : 8090;
app.use(bodyParser.json({ type: '*/*' }));
//setup Credentials object with newly created application identity.
var codes = [];
var credentials = new Credentials({
    appName: 'Request Verification Example',
    did: process.env.SERVER_DID,
    privateKey: process.env.SERVER_PRIVATE_KEY
});
app.use("/", express.static(__dirname + '/public'));
app.get('/api/disclosure', function (req, res) {
    var url = endpoint !== null ? endpoint : 'http://' + req.hostname + ':' + port;
    var code = randomstring.generate();
    console.log(Date.now());
    credentials.createDisclosureRequest({
        verified: ['didiserver'],
        exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24 * 365),
        callbackUrl: url + '/api/callback/' + code
    }).then(function (requestToken) {
        console.log(decodeJWT(requestToken)); //log request token to console
        var uri = message.paramsToQueryString(message.messageToURI(requestToken), { callback_type: 'post' });
        var qr = transports.ui.getImageDataURI(uri);
        codes.push({ code: code, status: false });
        success(res, { code: code, qr: qr, requestToken: requestToken });
    })["catch"](function (e) {
        console.error(e);
        error(res, 'Error interno');
    });
});
app.get('/api/check/:code', function (req, res) {
    var value = codes.find(function (c) { return c.code === req.params.code; });
    var reply = {
        status: value ? value.status : false,
        jwt: value ? value.jwt : ''
    };
    success(res, reply);
});
app.get('/api/credential_viewer/:token', function (req, res) {
    var jwt = req.params.token;
    did_jwt_vc_1.verifyCredential(jwt, resolver).then(function (verifiedVC) {
        var data = verifiedVC.payload.vc.credentialSubject;
        var issuer = verifiedVC.payload.iss;
        var nombre = didData.filter(function (it) { return it.did === issuer; });
        var name = "";
        if (nombre.length == 0) {
            name = issuer + " (emisor desconocido)";
        }
        else {
            name = nombre[0].name;
        }
        res.render("viewer.html", { iss: name, credential: data, error: false });
    })["catch"](function (err) {
        console.log(err);
        res.render("viewer.html", { iss: false, credential: false, error: err });
    });
});
app.post('/api/callback/:code', function (req, res) {
    var code = req.params.code;
    var jwt = req.body.access_token;
    console.log('[JWT]', jwt);
    console.log('[JWT decode]', decodeJWT(jwt));
    credentials.authenticateDisclosureResponse(jwt).then(function (creds) {
        //validate specific data per use case
        console.log('[credencial]', creds);
        //console.log(creds.verified[0])
        codes = __spreadArrays(codes.filter(function (c) { return c.code !== code; }), [{ code: code, jwt: jwt, status: true }]);
        success(res, true);
    })["catch"](function (err) {
        console.log(err);
        error(res, 'Error interno');
    });
});
app.post('/api/verify', function (req, res) {
    var jwt = req.body.jwt;
    did_jwt_vc_1.verifyCredential(jwt, resolver).then(function (verifiedVC) {
        var credential = verifiedVC.payload.vc.credentialSubject;
        console.log(credential);
        success(res, credential);
    });
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
});
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
app.listen(port, function () {
    if (process.env.DISABLE_NGROK) {
        console.log('Verification Service running, no NGROK', port);
    }
    else {
        ngrok.connect(port).then(function (ngrokUrl) {
            endpoint = ngrokUrl;
            console.log("Verification Service running, open at " + ngrokUrl);
        });
    }
});
