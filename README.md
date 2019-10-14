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
