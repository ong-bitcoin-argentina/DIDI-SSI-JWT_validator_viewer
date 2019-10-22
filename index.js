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

var http = require('follow-redirects').http;
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
var addEdge = require('./Mouro').addEdge;
var did_resolver_1 = require("did-resolver");
var ethr_did_resolver_1 = require("ethr-did-resolver");
var did_jwt_vc_1 = require("did-jwt-vc");
var EthrDID = require('ethr-did');
var app = express();
nunjucks.configure("public", { autoescape: true, express: app });
var resolver = new did_resolver_1.Resolver(ethr_did_resolver_1.getResolver());
var endpoint = null;
var port = process.env.PORT ? parseInt(process.env.PORT, 10) : 8080;
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
        var tipo =Object.keys(data)[0]
        var c_nombre= data[tipo].nombre
        var c_apellido= data[tipo].apellido
        var c_curso= data[tipo].curso
        var c_duracion= data[tipo].duracion
        var c_fecha_fin= data[tipo].fecha_fin
        var issuer = verifiedVC.payload.iss;
        var nombre = didData.filter(function (it) { return it.did === issuer; });
        var name = "";
        if (nombre.length == 0) {
            name = issuer + " (emisor desconocido)";
        }
        else {
            name = nombre[0].name;
        }
        res.render("viewer.html", { iss: name, tipo_credencial: tipo, nombre: c_nombre, apellido: c_apellido, curso: c_curso, duracion: c_duracion, fecha_fin: c_fecha_fin, error: false });
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

app.post('/api/callbackMouro', function (req, res) {
    var jwt = req.body.access_token;
    console.log('[JWT]', jwt);
    console.log('[JWT decode]', decodeJWT(jwt));
    credentials.authenticateDisclosureResponse(jwt).then(function (creds) {
        console.log('[credencial]', creds);
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
});
app.get('/api/disclosurebymouro/', function (req, res) {
    var url = endpoint !== null ? endpoint : 'http://' + req.hostname + ':' + port;
    credentials.createDisclosureRequest({
        verified: ['didiserver'],
        exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24 * 365),
        callbackUrl: url + '/api/callbackMouro/'
    }).then(function (requestToken) {
        console.log(requestToken)
        credentials.signJWT({
            "sub": req.query.did,
            'disclosureRequest': requestToken,
            exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24 * 30)
        }).then(function(token){
            var hash_mouro = addEdge(token)
            res.render("disclosurebymouro.html")
        })
    });
});

app.get('/api/mouroViewer/', function(req, res) {
    res.render('mouroViewer.html')
})

app.get('/api/myMouro/', function(req, res) {
    var did=  req.query.did
    var private_key= req.query.private_key 
    var vcissuer = new EthrDID({
        address: did,
        privateKey: private_key
    });
    vcissuer.signJWT({
        sub: "did:ethr:" + did,
        exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24 * 30) // what is a reasonable value here?
    }).then(function (token) {
        var input='{"query": "{findEdges(toDID: ["did:ethr:' + did + '"]){hash,jwt,from {did},to {did},type,time,visibility,retention,tag,data }}"}'
        const request = require('request');
        request.post('http://edge.uport.me', {'auth': {'bearer': token, 'sendInmediately': true},'body': input, 'followAllRedirects':true},function(error,response,body) {
            console.log(body);
        })
    });
    
    res.render("myMouro.html")
})


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
