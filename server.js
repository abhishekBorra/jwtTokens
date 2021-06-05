require('dotenv').config()

const express = require('express')
const app = express()

const jwt = require('jsonwebtoken')

app.use(express.json())

//for testing the app running status
app.get('/test', (req, res) => {
    res.send('Connecting successfully!!!')
})

//validate the user and create device token
app.post('/validate', (req, res) => {
    
    const mobile = req.body.mobile
    const otp = req.body.otp

    if (!mobile || !otp) return res.sendStatus(401)
    if (otp !== 1234) return res.sendStatus(403)

    const deviceToken = generateDeviceToken({ mobile: mobile })

    res.json({ deviceToken: deviceToken })
})

//validate the device token. Valdiate tnc and create userId and access token
app.post('/tnc', authenticateDeviceToken, (req, res) => {
    const mobile = req.body.mobile
    const tnc = req.body.tnc

    if (!mobile || tnc == null) return res.sendStatus(401)
    if (tnc !== true) return res.sendStatus(403)

    const userId= Math.floor(Math.random() * 1000) + 1

    const accessToken = generateAccessToken({ mobile: mobile, userId: userId })
    const refreshToken = generateRefreshToken({ mobile: mobile, userId: userId })

    res.json({ accessToken: accessToken, refreshToken: refreshToken })
})

//validate the device token and access token. Start business logic
app.post('/profile', authenticateDeviceToken, authenticateAccessToken, (req, res) => {
    const userId = req.body.userId
    const firstName = req.body.firstName
    const lastName = req.body.lastName

    if (!userId || !firstName || !lastName) return res.sendStatus(401)
    
    res.send(`Hello ${firstName} ${lastName} (${userId})!! Start writing your business logic`)
})

//generate new access token with refresh token
app.post('/refresh', authenticateDeviceToken, (req, res) => {
    
    const RefreshTokenHeader = req.headers['refreshtoken']
    const RefreshToken = RefreshTokenHeader && RefreshTokenHeader.split(' ')[1]
    if(RefreshToken == null) return res.sendStatus(401)

    jwt.verify(RefreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if(err) return res.sendStatus(403)

        //Prepare parameter with similar details which are used to create access token at first time
        const accessToken = generateAccessToken({ mobile: user.mobile, userId: user.userId })
        res.json({ accessToken: accessToken })
    })
})

//generate device token. never expire
function generateDeviceToken(user) {
    return jwt.sign(user, process.env.DEVICE_TOKEN_SECRET)
}

//validate device token
function authenticateDeviceToken(req, res, next) {
    const deviceTokenHeader = req.headers['devicetoken']
    const deviceToken = deviceTokenHeader && deviceTokenHeader.split(' ')[1]
    if(deviceToken == null) return res.sendStatus(401)

    jwt.verify(deviceToken, process.env.DEVICE_TOKEN_SECRET, (err, user) => {
        if(err) return res.sendStatus(403)
        req.body.mobile = user.mobile
        next()
    })
}

//generate access token
function generateAccessToken(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '60s' })
}

//validate access token
function authenticateAccessToken(req, res, next) {
    const AccessTokenHeader = req.headers['accesstoken']
    const AccessToken = AccessTokenHeader && AccessTokenHeader.split(' ')[1]
    if(AccessToken == null) return res.sendStatus(401)

    jwt.verify(AccessToken, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if(err) return res.sendStatus(403)
        req.body.mobile = user.mobile
        req.body.userId = user.userId
        next()
    })
}

//generate refresh token
function generateRefreshToken(user) {
    return jwt.sign(user, process.env.REFRESH_TOKEN_SECRET)
}

app.listen(3000)

//test