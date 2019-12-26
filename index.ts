// Environment required
if (!process.env.SERVER_DID || !process.env.SERVER_PRIVATE_KEY) {
	throw new Error(
		"Faltan las variables de entorno SERVER_DID y SERVER_PRIVATE_KEY"
	);
}

const log = console.log;
console.log = function(data: any) {
	log(new Date().toISOString() + ": " + data);
};

var fetch = require("node-fetch");
const express = require("express");
const bodyParser = require("body-parser");
const ngrok = require("ngrok");
const decodeJWT = require("did-jwt").decodeJWT;
const { Credentials } = require("uport-credentials");
const transports = require("uport-transports").transport;
const message = require("uport-transports").message.util;
const randomstring = require("randomstring");
var EthrDID = require("ethr-did");

const { success, error } = require("./Utils");

const nunjucks = require("nunjucks");

const { addEdge, fetchEdges } = require("./Mouro");

import { verifyCredential } from "did-jwt-vc";

const app = express();

nunjucks.configure("public", { autoescape: true, express: app });

var did_resolver_1 = require("did-resolver");
var ethr_did_resolver_1 = require("ethr-did-resolver");
var resolver = new did_resolver_1.Resolver(ethr_did_resolver_1.getResolver());

let endpoint = null;
let port = process.env.PORT ? parseInt(process.env.PORT, 10) : 8080;

app.use(bodyParser.json());
//setup Credentials object with newly created application identity.

let codes = [];
const credentials = new Credentials({
	appName: "Request Verification Example",
	did: process.env.SERVER_DID,
	privateKey: process.env.SERVER_PRIVATE_KEY
});

app.use("/", express.static(__dirname + "/public"));
app.get("/api/disclosure", (req, res) => {
	let url = endpoint !== null ? endpoint : "http://" + req.hostname + ":" + port;
	let code = randomstring.generate();
	console.log(Date.now());
	credentials
		.createDisclosureRequest({
			verified: ["didiserver"],
			exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 365,
			callbackUrl: url + "/api/callback/" + code
		})
		.then(requestToken => {
			console.log(decodeJWT(requestToken)); //log request token to console
			const uri = message.paramsToQueryString(message.messageToURI(requestToken), {
				callback_type: "post"
			});
			const qr = transports.ui.getImageDataURI(uri);
			codes.push({ code, status: false });
			success(res, { code, qr, requestToken });
		})
		.catch(e => {
			console.error(e);
			error(res, "Error interno");
		});
});

app.get("/api/check/:code", (req, res) => {
	let value = codes.find(c => c.code === req.params.code);
	let reply = {
		status: value ? value.status : false,
		jwt: value ? value.jwt : ""
	};
	success(res, reply);
});

const verifyCert = function(cert, cb, errCb) {
	const route = process.env.DIDI_API + "issuer/verifyCertificate";

	fetch(route, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({
			jwt: cert
		})
	})
		.then(response => {
			return response.json();
		})
		.then(res => {
			if (res.status === "error") return errCb(res);

			if (res.data.err) {
				return cb(res.data.cert, res.data.err.message);
			} else {
				return cb(res.data);
			}
		})
		.catch(err => {
			console.log(err);
			return errCb(err);
		});
};

app.get("/api/credential_viewer/:token", function(req, res) {
	var jwt = req.params.token;
	console.log("[credential_viewer]", jwt);

	verifyCert(
		jwt,
		function(result, err) {
			var data = result.payload.vc.credentialSubject;

			const credential = Object.values(data)[0];
			const credentialPreview = credential["preview"]
				? credential["preview"]
				: { fields: [] };

			const credentialData = credential["data"];
			const credentialDataKeys = Object.keys(credentialData).sort((a, b) => {
				return credentialPreview["fields"].indexOf(b) >=
					credentialPreview["fields"].indexOf(a)
					? 1
					: -1;
			});

			for (let key of credentialDataKeys) {
				credentialData[key] = {
					data: credentialData[key],
					toPreview: credentialPreview["fields"].indexOf(key) >= 0
				};
			}

			res.render("viewer.html", {
				iss: result.issuer ? result.issuer : false,
				credentialData: credentialData,
				credentialDataKeys: credentialDataKeys,
				credentialPreview: credentialPreview,
				error: err ? err : false
			});
		},
		function(err) {
			return res.render("viewer.html", {
				iss: false,
				credential: false,
				error: err.message
			});
		}
	);
});

app.post("/api/callback/:code", (req, res) => {
	const code = req.params.code;
	const jwt = req.body.access_token;
	console.log("[JWT]", jwt);
	console.log("[JWT decode]", decodeJWT(jwt));
	credentials
		.authenticateDisclosureResponse(jwt)
		.then(creds => {
			//validate specific data per use case
			console.log("[credencial]", creds);
			//console.log(creds.verified[0])
			codes = [...codes.filter(c => c.code !== code), { code, jwt, status: true }];
			success(res, true);
		})
		.catch(err => {
			console.log(err);
			error(res, "Error interno");
		});
});

app.post("/api/verify", (req, res) => {
	let jwt = req.body.jwt;

	verifyCredential(jwt, resolver).then(function(verifiedVC) {
		var credential = verifiedVC.payload.vc.credentialSubject;
		console.log(credential);
		success(res, credential);
	});
});

app.get("/api/disclosurebymouro/", (req, res) => {
	let url = endpoint !== null ? endpoint : "http://" + req.hostname + ":" + port;
	credentials
		.createDisclosureRequest({
			verified: ["didiserver"],
			exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 365,
			callbackUrl: url + "/api/callback/"
		})
		.then(requestToken => {
			var hash_mouro = addEdge(requestToken, req.query.did);
			console.log(hash_mouro);
		});
});

app.get("/api/mouroViewer", function(req, res) {
	res.render("mouroViewer.html");
});

app.post("/api/myMouro", function(req, res) {
	var did = req.body.did;
	var private_key = req.body.private_key;

	console.log("keys", did, private_key);
	var vcissuer = new EthrDID({
		address: did,
		privateKey: private_key
	});

	vcissuer
		.signJWT({
			sub: "did:ethr:" + did,
			exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 30 // what is a reasonable value here?
		})
		.then(
			token => fetchEdges(did, token)
			/*var input = '{"query": "{findEdges(toDID: ["did:ethr:' + did + '"]){hash,jwt,from {did},to {did},type,time,visibility,retention,tag,data }}"}'
    const request = require('request');
    request.post('http://edge.uport.me', { 'auth': { 'bearer': token, 'sendInmediately': true }, 'body': input, 'followAllRedirects': true }, function (error, response, body) {
      console.log(body);
    })*/
		)
		.then(body => {
			console.log(body.data.findEdges);
			if (body.errors) {
				return error(res, body.errors);
			}
			success(res, body.data.findEdges);
			//res.render("myMouro.html", { edges: body.data.findEdges })
		})
		.catch(e => {
			console.error(e);
			res.render("error.html");
		});
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
		console.log("Verification Service running, no NGROK", port);
	} else {
		ngrok.connect(port).then(ngrokUrl => {
			endpoint = ngrokUrl;
			console.log(`Verification Service running, open at ${ngrokUrl}`, port);
		});
	}
});
