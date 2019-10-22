const fetch = require('node-fetch');

const uri = 'https://edge.uport.me/graphql'
const query = "mutation{addEdge(edgeJWT: \"{edgeJWT}\"){hash,jwt,from {did},to{did},type,time,visibility,retention,tag,data}}"


function addEdge(jwt) {
  var temp = query.replace('{edgeJWT}', jwt)
  let data = {
    query: temp
  }

  console.log(data)
  fetch(uri, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  }).then(res => res.json()).then(json => {
    let data = json.data
    console.log('hash [' + data.addEdge.hash + ']')
  })

}

module.exports = { addEdge }