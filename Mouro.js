const fetch = require('node-fetch');

const uri = 'https://edge.uport.me/graphql'
const query = "mutation{addEdge(edgeJWT: \"{edgeJWT}\"){hash,jwt,from {did},to{did},type,time,visibility,retention,tag,data}}"

const fetchQuery = '{findEdges(toDID: ["did:ethr:{did}"]){hash,jwt,from {did},to {did},type,time,visibility,retention,tag,data }}'


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

function fetchEdges(did, token) {
  let data = {
    query: fetchQuery.replace('{did}', did)
  }

  console.log(data)
  return fetch(uri, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + token
    },
    body: JSON.stringify(data)
  }).then(res => res.json())
}

module.exports = { addEdge, fetchEdges }