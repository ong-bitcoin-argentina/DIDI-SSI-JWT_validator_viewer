"use strict";

const log = console.log;
console.log = function (data) {
	log(new Date().toISOString() + ": ");
	log(data);
	log();
};

exports.__esModule = true;

var _a = require("./Utils"),
	success = _a.success;

var fetch = require("node-fetch");
var express = require("express");
var bodyParser = require("body-parser");
var nunjucks = require("nunjucks");
var app = express();
nunjucks.configure("public", { autoescape: true, express: app });

var port = process.env.PORT ? parseInt(process.env.PORT, 10) : 8080;
app.use(bodyParser.json());

app.use("/", express.static(__dirname + "/public"));

const verifyCert = function (cert, micros, cb, errCb) {
	const route = process.env.DIDI_API + "issuer/verifyCertificate";

	fetch(route, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({
			jwt: cert,
			micros: micros,
		}),
	})
		.then((response) => {
			return response.json();
		})
		.then((res) => {
			if (res.status === "error") return errCb(res);

			if (res.data.err) {
				return cb(res.data.cert, res.data.err.message);
			} else {
				return cb(res.data);
			}
		})
		.catch((err) => {
			console.log(err);
			return errCb(err);
		});
};

/**
 * Envia al didi-server un pedido para realizar un disclosureRequest
 * al dueño del credencial para que valide que es suyo y los datos que contiene son correctos
 */
app.post("/api/credential_viewer/sendVerifyRequest", function (req, res) {
	const route = process.env.DIDI_API + "verifyCredentialRequest";

	fetch(route, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({
			did: req.body.did,
			jwt: req.body.jwt,
		}),
	})
		.then((_) => {
			success(res, {});
		})
		.catch((err) => {
			console.log(err);
		});
});

/**
 * Envia al didi-server los credenciales para ser validados y
 * muestra el contenido de cada uno de ellos y/o el error que este retorna
 */
app.get("/api/credential_viewer/:tokens/", async function (req, res) {
	var jwts = req.params.tokens.split(",");
	var micros = undefined;

	const translations = {
		streetAddress: "calle",
		numberStreet: "número",
		floor: "piso",
		department: "departamento",
		zipCode: "código zip",
		city: "ciudad",
		municipality: "municipalidad",
		province: "provincia",
		country: "país",
		gender: "genero",
		names: "nombres",
		lastNames: "apellidos",
		birthdate: "cumpleaños",
		nationality: "nacionalidad",
		countryBirth: "país de origen",
		phoneNumber: "telefóno",
		email: "mail",
	};

	const promises = [];
	for (let jwt of jwts) {
		console.log(jwt);
		const promise = new Promise(function (resolve, reject) {
			verifyCert(
				jwt,
				micros,
				function (result, err) {
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

					console.log(data);

					const keys = [];
					for (let key of credentialDataKeys) {
						const newKey = translations[key] ? translations[key] : key;
						keys.push(newKey);
						credentialData[newKey] = {
							data: translateField(credentialData[key]),
							toPreview: credentialPreview["fields"].indexOf(key) >= 0,
						};
					}

					resolve({
						jwt: jwt,
						did: result.payload.sub,
						iss: result.issuer ? result.issuer : false,
						credentialData: credentialData,
						credentialDataKeys: keys,
						status: result.status,
						error: err ? err : false,
					});
				},
				function (err) {
					resolve({
						iss: false,
						credential: false,
						error: err.message,
					});
				}
			);
		});
		promises.push(promise);
	}

	try {
		const result = await Promise.all(promises);
		res.render("viewer.html", {
			data: result,
		});
	} catch (err) {
		return res.render("viewer.html", {
			iss: false,
			credential: false,
			error: err.message,
		});
	}
});

const translateField = function (data) {
	const dateRegex = /\d{4}-[01]\d-[0-3]\dT[0-2]\d:[0-5]\d:[0-5]\d([+-][0-2]\d:[0-5]\d|Z)/;
	if (data.match(dateRegex)) {
		const date = new Date(data);
		return formatFullDate(date);
	}

	if (data === "true" || data === "false") {
		return data === "true" ? "si" : "no";
	} else {
		return data;
	}
};

const formatDatePart = function(date) {
	const months = [
		"Enero",
		"Febrero",
		"Marzo",
		"Abril",
		"Mayo",
		"Junio",
		"Julio",
		"Agosto",
		"Septiembre",
		"Octubre",
		"Noviembre",
		"Diciembre"
	];
	return `${date.getDay()} de ${months[date.getMonth()]} de ${date.getFullYear()}`;
}

const formatHourPart = function(date) {
	const pad = (n) => (n < 10 ? `0${n}` : n);
	return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

const formatFullDate = function(date) {
	return `${formatDatePart(date)}, ${formatHourPart(date)}`;
}

app.listen(port, function () {
	console.log("Verification Service running", port);
});
