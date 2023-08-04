import cors from 'cors'
import express from 'express'
import request from 'request'

const app = express()
const port = 3001

const CLIENT_ID = process.env.CLIENT_ID
const CLIENT_SECRET = process.env.CLIENT_SECRET
const REDIRECT_URI = process.env.REDIRECT_URI

app.use(cors())

app.get('/auth/etsy', (req, res) => {
  res.redirect(
    `https://www.etsy.com/oauth/connect?client_id=${CLIENT_ID}&response_type=code&redirect_uri=${REDIRECT_URI}`
  )
})

app.get('/auth/etsy/callback', (req, res) => {
  const code = req.query.code as string

  request.post(
    {
      url: 'https://api.etsy.com/v3/public/oauth/token',
      form: {
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        redirect_uri: REDIRECT_URI,
        code: code,
        grant_type: 'authorization_code'
      }
    },
    (error, response, body) => {
      const accessToken = JSON.parse(body).access_token
      res.redirect(`http://localhost:3000/orders?token=${accessToken}`)
    }
  )
})

app.listen(port, () => console.log(`Server running on port ${port}`))
