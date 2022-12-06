const express = require('express')
const cors = require('cors')
const axios = require('axios')
const bodyParser = require('body-parser')
const config = require("../config.js")
const { Issuer, generators } = require('openid-client')

const app = express()
app.use(cors())
app.use(bodyParser.json()) // support json encoded bodies
app.use(bodyParser.urlencoded({ extended: true })) // support encoded bodies

let client
let currentTokenSet
const state = generators.state()
const nonce = generators.nonce()

Issuer.discover(config.auth_service.issuer) // => Promise
  .then(function (Issuer) {
    console.log('Discovered issuer %s %O', Issuer.issuer, Issuer.metadata);
    client = new Issuer.Client({
      client_id: config.auth_service.client_id,
      client_secret: config.auth_service.client_secret,
      redirect_uris: [`${config.frontend.url}/oauth-callback`], //frontend-callback
      post_logout_redirect_uris: [`${config.frontend.url}/`], //frontend-home-page
      response_types: ['code'],
    }) // => Client
  }).catch(err => {
    console.log(err)
  })

// Utility function to parse JWT tokens 
const getParsedJwt = (token) => {
  try {
    return JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString())
  } catch (e) {
    return undefined
  }
}

const printTokenset = (tokenSet) => {
  currentTokenSet = tokenSet
  console.log("\n-------------------------TOKEN SET-------------------------")
  console.log(tokenSet)
  console.log("\n----------------------ID TOKEN CLAIMS----------------------")
  console.log(tokenSet.claims())
}

// Protect endpoinds from unauthenticated users
const requireAuthN = (req, res, next) => {
  let access_token = req.headers["authorization"].split(" ")[1]
  client.introspect(access_token)
    .then((isVerified) => {
      if (isVerified.active) {
        console.log(isVerified.active)
        next()
      }
      else {
        try {
          if (currentTokenSet.expired()) {
            console.log("Trying to refresh token because of expiration")
            client.refresh(currentTokenSet["refresh_token"]) // => Promise
              .then((tokenSet) => {
                console.log("Token has been refreshed successfuly")
                printTokenset(tokenSet)
                req.access_token = tokenSet["access_token"]
                next()
              }).catch(err => {
                console.log(err)
              })
          }
        } catch (e) {
          console.log(isVerified)
          return res.status(401).send('Invalid token')
        }
      }
    }).catch(err => {
      console.log(err)
    })
}

// Protect endpoinds from unauthorized users
// This is a basic example, it doesn't check recursive objects
// Method option types:
// ALL - all the other options should be in the given token
// ONE - at least one option should be in the given token
const requireAuthZ = options => {
  return (req, res, next) => {
    let method = options["method"]
    if (method !== "ALL" && method !== "ONE") {
      throw `method should be either "ALL" or "ONE" and not ${method}`;
    }

    let claim_check = []
    const access_token = req.headers["authorization"].split(" ")[1]
    const parsetAccess_token = getParsedJwt(access_token)
    for (const [key, value] of Object.entries(options)) {
      if (key !== "method") {
        try {
          if (parsetAccess_token[key].includes(value)) {
            console.log(`The user has the claim ${key} with the value ${value}`)
            claim_check.push(true)
          }
          else {
            throw `The user doesn't have the claim ${key} with the value ${value}`
          }
        } catch (e) {
          console.log(`The user doesn't have the claim ${key} with the value ${value}`)
          claim_check.push(false)
        }
      }
    }

    if ((claim_check.some(item => item === true) && method === "ONE") || (claim_check.every(item => item === true) && method === "ALL")) {
      next()
    } else {
      res.status(403).send("Forbidden")
    }
  }
}

app.get('/login', (req, res) => {
  let authUrl = client.authorizationUrl({
    scope: 'openid',
    state,
    nonce
  })
  res.send(authUrl)
})

app.post('/code-to-token-exchange', (req, res) => {
  const params = client.callbackParams(req);
  client.callback(`${config.frontend.url}/oauth-callback`, params, { state, nonce })
    .then((tokenSet) => {
      printTokenset(tokenSet)
      res.send(tokenSet["access_token"])
    }).catch(err => {
      console.log(err)
    })
})

app.get('/logout', (req, res) => {
  console.log("Logging out of session")
  currentTokenSet = undefined // Clearence of the saved tokens
  res.send(client.endSessionUrl())
})

// Anyone can access this route
app.get('/public', (req, res) => {
  return res.json({ message: 'This is a public endpoint, therefore everyone has access to it.' })
});

// For a protected endpoint you should return also an access token, like it is shown in the below endpoints 
// and thats because there is a chance that your token is expired and the refresh process started 
// and it returns with the message a new access token.
// If there won't be a new access token so the json you will recieve in the frontend is just { message: 'your message' }

// A protected endpoint, just authentication ( this endpoint checks that the given token is valid )
app.get('/protected', requireAuthN, (req, res) => {
  res.json({ message: 'Hey there authenticated user', access_token: req["access_token"] })
});

// // TRY IT YOURSELF, uncomment this section and comment all others protected endpoints 
// // A protected endpoint, authentication and authorization 
// // ( this endpoint checks that the given token is valid, and that at least one of the given claims exists in the token )
// // !NOT INCLUDING THE METHOD OPTION!
// // @see requireAuthZ
// app.get('/protected', requireAuthN, requireAuthZ({ method: 'ONE', group: 'testgroup', preferred_username: 'emp' }), (req, res) => {
//   res.json({ message: 'Hey there authenticated user', access_token: req["access_token"] })
// });

// // TRY IT YOURSELF, uncomment this section and comment all others protected endpoints 
// // A protected endpoint, authentication and authorization 
// // ( this endpoint checks that the given token is valid, and that all of the given claims exists in the token )
// // !NOT INCLUDING THE METHOD OPTION!
// // @see requireAuthZ
// app.get('/protected', requireAuthN, requireAuthZ({ method: 'ALL', group: 'testgroup', preferred_username: 'emp' }), (req, res) => {
//   res.json({ message: 'Hey there authenticated user', access_token: req["access_token"] })
// });

const hardCodedData = {
  resources: {
    testresource: {
      DB: "My PGSQL Database ",
      Location: "Italy, Rome",
      Flavor: "2xLarge"
    }
  }
}


let PAT = ''

function isTokenLocallyValid(token) {
  try {
    return getParsedJwt(token).exp > Date.now() / 1000
  }
  catch {
    return false
  }
}

async function getPat() {
  if (isTokenLocallyValid(PAT)) {
    return PAT
  }
  else {
    var data = `grant_type=client_credentials&client_id=${config.auth_service.client_id}&client_secret=${config.auth_service.client_secret}`

    var axiosconfig = {
      method: 'post',
      url: `${config.auth_service.issuer}/protocol/openid-connect/token`,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      data: data
    }
    return await axios(axiosconfig)
      .then((res) => {
        PAT = res.data.access_token
        return PAT
      }).catch(err => {
        console.log(err)
      })
  }
}

async function getResourceId(resource_name) {
  var axiosconfig = {
    method: 'get',
    url: `${config.auth_service.issuer}/authz/protection/resource_set?name=${resource_name}&exactName=true`,
    headers: {
      'Authorization': `Bearer ${await getPat()}`
    },
  };


  return axios(axiosconfig)
    .then((res) => {
      return res.data[0]
    }).catch(err => {
      console.log(err);
    })
}

async function requestTicket(requestedResources) {


  //let resource_id = await getResourceId(resource_name)

  let data = []

  resourceIdPromises = requestedResources.map(x => getResourceId(x.resource_name))

  await Promise.all(resourceIdPromises).then(values => {
    for (let i = 0; i < values.length; i++) {
      data.push({resource_id: values[i], resource_scopes: requestedResources[i].resource_scopes});
    }
  })

  var axiosconfig = {
    method: 'post',
    url: `${config.auth_service.issuer}/authz/protection/permission`,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${await getPat()}`
    },
    data: data
  };

  return axios(axiosconfig)
    .then(function (response) {
      return response.data.ticket
    })
    .catch(err => {
      console.log(err)
    })

}

async function authorizeToken(token, resource_name, scopes) {


  // TODO: MAKE THE FUNCTION ABLE TO UPGRADE EXISTING RPTs
  requestedResources = [
    {
      resource_name: resource_name,
      resource_scopes: scopes
    }
  ]
  if (getParsedJwt(token).authorization) {
    getParsedJwt(token).authorization.permissions.forEach(permission => {
      requestedResources.push({ resource_name: permission.rsname, resource_scopes: [] })
    })
  }
  ticket = await requestTicket(requestedResources)

  var data = `grant_type=urn:ietf:params:oauth:grant-type:uma-ticket&submit_request=true&ticket=${ticket}`;

  var axiosconfig = {
    method: 'post',
    url: `${config.auth_service.issuer}/protocol/openid-connect/token`,
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': `Bearer ${token}`
    },
    data: data
  };

  return axios(axiosconfig)
    .then(function (response) {
      return response.data
    })
  .catch(function (error) {
    console.log(error);
  });



}

app.get('/resources/*', (req, res) => {
  requested_resource = req.params[0]
  access_token = req.headers.authorization.split(" ").pop()
  if (req.query.scopes) {
    scopes = req.query.scopes.split(",")
  } else {
    scopes = []
  }
  introspection = client.introspect(access_token)
    .then((res2) => {
      if (res2.active == true) {
        if (getParsedJwt(access_token).authorization && getParsedJwt(access_token).authorization.permissions.find(element => element.rsname == requested_resource)) {
          data = hardCodedData.resources[requested_resource]
          res.json({ requested_resource: requested_resource, data: data })
        }
        else {
          authorizeToken(access_token, requested_resource, scopes).then((res3) => {
            res.json(res3)
          }).catch(err => {
            res.status(err.response.status).json(err.response.data)
          })
        }
      }
      else {
        res.status(401).json({ error: "Token is inactive" })
      }
    }).catch(err => {
      console.log(err)
      res.status(500).json({ error: "Instrospection failed" })
    });
})

app.post('/resources/*', (req, res) => {
  requested_resource = req.url.split('/').pop()
  access_token = req.headers.authorization.split(" ").pop()
  introspection = client.introspect(access_token)
    .then((res2) => {
      if (res2.active == true) {
        getPat().then(() => {
          var data = {
            owner: req.body.owner,
            name: req.body.name,
            resource_scopes: req.body.resource_scopes
          };

          var axiosconfig = {
            method: 'post',
            url: `${config.auth_service.issuer}/authz/protection/resource_set/`,
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${PAT}`
            },
            data: data
          };

          axios(axiosconfig)
            .then(function (response) {
              res.json({ result: "created" })
              hardCodedData[requested_resource] = req.body.data
            })
        })
      }
      else {
        res.status(401).json({ error: "Token is incative" })
      }
    }).catch(err => {
      console.log(err)
      res.status(500).json({ error: "Instrospection failed" })
    });
})

app.listen(config.backend.port, () => {
  console.log(`Example app listening at ${config.backend.url}`)
})