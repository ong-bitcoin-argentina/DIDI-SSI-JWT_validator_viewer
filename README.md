# Didi jwt validator viewer

## Variables de entorno

SERVER_DID
SERVER_PRIVATE_KEY
TMP_DID (did contra el que se valida el issuer, temporal mientras se construye la validacion)


## Ejecutar local
```
node start
```

## Ejecutar docker
```
sudo docker run -d -p 8090:8090 -e 'SERVER_DID=did:ethr:0x3148...'  -e 'SERVER_PRIVATE_KEY=ef6a...' -e 'TMP_DID=did:ethr:0x2084...' didi-jwt-validator-viewer
```
