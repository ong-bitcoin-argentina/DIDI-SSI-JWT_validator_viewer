# Didi jwt validator viewer

## Variables de entorno
DIDI_API

## Ejecutar local
```
npm run local
```

## Ejecutar docker
```
sudo docker run -d -p 8090:8090 -e 'DIDI_API=http://localhost:3000/api/1.0/didi/' didi-jwt-validator-viewer
```
