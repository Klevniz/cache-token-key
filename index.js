const express = require("express")
const jwt = require("jsonwebtoken")
require("dotenv").config()
const NodeCache = require('node-cache');
const cache = new NodeCache();
const app = express()
app.use(express.json())

  
const port = process.env.PORT || 3000

const companies = [
  { id: 1, name: "Rhode", refresh: null },
  { id: 2, name: "ICM", refresh: null }
]
app.listen(port, () => {
  console.log(`app listening on port ${port}`)
})

app.post("/auth/login", (req, res) => {
    const { name } = req.body
  
  //find company 
    const company = companies.findIndex((e) => e.name === name)
  
    if (!name || company < 0) {
      return res.send(400)
    }
  
    const access_token = jwtGenerate(companies[company])
  
    res.json({
      access_token
    })
  })

  const jwtGenerate = (company) => {
    let access_token
    if(company.name === 'Rhode'){
        access_token = process.env.RHODE_TOKEN_SECRET
    }
    else{
        access_token = process.env.ICM_TOKEN_SECRET
    }
    const accessToken = jwt.sign(
      { name: company.name, id: company.id },
      access_token,
      { expiresIn: "3m", algorithm: "HS256" }
    )
  
    return accessToken
  }
  
  const jwtValidate = (req, res, next) => {
    try {
      if (!req.headers["authorization"]) return res.sendStatus(401)
  
      const token = req.headers["authorization"].replace("Bearer ", "")
      const claims = JSON.parse(atob(token.split('.')[1]))
      let key
      if(claims.name === 'Rhode'){
        const rhode_key = cache.get('rhode_key')
        if(rhode_key !== undefined){
            console.log('found rhode_key cache. no need to request key from provider')
            key = rhode_key
        }
        else {
            key = process.env.RHODE_TOKEN_SECRET
            cache.set( "rhode_key", key, 30 )
            console.log('cache rhode_key for 30 seconds')
        }
      }
      else if(claims.name === 'ICM') {
        const icm_key = cache.get('icm_key')
        if(icm_key !== undefined){
            console.log('found icm_key cache. no need to request key from provider')
            key = icm_key
        }
        else{
            key = process.env.ICM_TOKEN_SECRET
            cache.set( "icm_key", key, 30 )
            console.log('cache icm_key for 30 seconds')
        }

      }
      else{
        throw new Error('Unauthorize JWT provider')
      }
      jwt.verify(token, key, (err, decoded) => {
        if (err) throw new Error(err)
      })
      next()
    } catch (error) {
      if(error.message){
        res.status(401)
        return res.send(error.message)
      }
      else{
        return res.sendStatus(403)
      }

    }
  }
  app.get("/", jwtValidate, (req, res) => {
    res.send("Hello World!")
  })

  