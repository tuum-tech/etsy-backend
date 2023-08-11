import cors from 'cors'
import crypto from 'crypto'
import dotenv from 'dotenv'
import express from 'express'
import session from 'express-session' // <-- Import this
import request from 'request'
import { CustomSession } from './express'

dotenv.config()

const app = express()
const port = 3001

const CLIENT_ID = process.env.CLIENT_ID
const CLIENT_SECRET = process.env.CLIENT_SECRET
const REDIRECT_URI = process.env.REDIRECT_URI

// To safely use the Authorization header in Express, we will want to trust the proxy when
// we are behind one, like when we're using load balancers.
app.set('trust proxy', 1)

// Setup express-session middleware
app.use(
  session({
    secret: 'your_session_secret', // TODO: Choose a strong secret here
    resave: false,
    saveUninitialized: true
  })
)

// Since we are making requests from a different origin (frontend on port 3000 and backend
// on port 3001), we'll want to ensure that the CORS settings allow for the Authorization
// header and other necessary headers/methods.
app.use(
  cors({
    origin: 'http://localhost:3000', // Assuming our frontend is served on this origin
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization']
  })
)

app.use(cors())

function generateStateToken() {
  return crypto.randomBytes(16).toString('hex')
}

function generateCodeVerifier() {
  return crypto.randomBytes(64).toString('hex')
}

function generateCodeChallenge(verifier: string) {
  return crypto
    .createHash('sha256')
    .update(verifier)
    .digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '')
}

app.get('/auth/etsy', (req, res) => {
  const state = generateStateToken()
  const codeVerifier = generateCodeVerifier()
  const codeChallenge = generateCodeChallenge(codeVerifier)

  req.session.state = state // // Save the state in the session
  req.session.codeVerifier = codeVerifier // Save the verifier in the session

  res.redirect(
    `https://www.etsy.com/oauth/connect?client_id=${CLIENT_ID}&response_type=code&redirect_uri=${REDIRECT_URI}&state=${state}&scope=address_r+billing_r+cart_r+email_r+favorites_r+feedback_r+listings_r+profile_r+recommend_r+shops_r+transactions_r&code_challenge=${codeChallenge}&code_challenge_method=S256`
  )
})

app.get('/auth/etsy/callback', (req, res) => {
  const returnedState = req.query.state as string
  const session = req.session as CustomSession
  const savedState = session?.state // Use optional chaining just in case

  if (returnedState !== savedState) {
    res.status(400).send('Invalid state parameter.')
    return
  }

  const code = req.query.code as string

  request.post(
    {
      url: 'https://api.etsy.com/v3/public/oauth/token',
      form: {
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        redirect_uri: REDIRECT_URI,
        code: code,
        code_verifier: req.session.codeVerifier, // Send the code_verifier
        grant_type: 'authorization_code'
      }
    },
    (error, response, body) => {
      if (error) {
        res.status(500).send('Error fetching access token.')
        return
      }

      const accessToken = JSON.parse(body).access_token
      if (!accessToken) {
        res.status(500).send('Access token not found in Etsy response.')
        return
      }
      res.redirect(`http://localhost:3000/orders?token=${accessToken}`)
    }
  )
})

app.get('/api/orders', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1] // Get Bearer token from header

  if (!token) {
    return res.status(401).send('Authorization token missing.')
  }

  // Call Etsy API to retrieve the user's shop ID first
  request.get(
    {
      url: 'https://openapi.etsy.com/v3/application/users/me',
      headers: {
        'x-api-key': CLIENT_ID, // Add this header
        Authorization: `Bearer ${token}`
      }
    },
    (error, response, body) => {
      if (error) {
        return res.status(500).send('Error fetching shop details.')
      }

      const userData = JSON.parse(body)
      console.log('Etsy User Data:', userData) // Log the data for debugging

      if (!userData.results || userData.results.length === 0) {
        return res
          .status(404)
          .json({ error: 'No shop details found for user.' })
      }

      const shopId = userData.results[0].primary_shop_id // Extracting primary shop ID from user's data

      // Now fetch the orders using shopId
      request.get(
        {
          url: `https://openapi.etsy.com/v3/application/shops/${shopId}/receipts`,
          headers: {
            Authorization: `Bearer ${token}`
          }
        },
        (error, response, body) => {
          if (error) {
            return res.status(500).send('Error fetching orders.')
          }
          const orderData = JSON.parse(body)
          res.json(orderData) // Return order data to frontend
        }
      )
    }
  )
})

app.listen(port, () => console.log(`Server running on port ${port}`))
