# Didi jwt validator viewer

## Variables de entorno

SERVER_DID
SERVER_PRIVATE_KEY
DISABLE_NGROK : si esta definida deshabilita ngrok


## Ejecutar local
```
node start
```

## Ejecutar docker
```
sudo docker run -d -p 8090:8090 -e 'SERVER_DID=did:ethr:0x3148...'  -e 'SERVER_PRIVATE_KEY=ef6a...' didi-jwt-validator-viewer
```

# Verificación vía Mouro

* Ingrese a la URL raíz de la aplicación
* Ingrese su DID en el campo de texto
* Se emitirá un disclosureRequest vía Mouro. Su aplicación móvil puede leer mediante la llamada findEdges todos los attestation emitidos a su nombre

# Verificación y validación de credenciales

* El sistema valida tanto credenciales en formato uport (https://github.com/uport-project/uport-credentials) como verifiable credentials (https://github.com/decentralized-identity/did-jwt-vc)

* URL verificador:

http://HOST/api/credential_viewer/JWT_A_VALIDAR

* Configuración de identidades

Para este prototipo, se incluyó en el servicio un archivo did.json, que contiene un listado de DIDs que serán reconocidos como emisores válidos. En caso que el DID del verifiable claim no esté incluido, se mostrará una alerta al usuario.
