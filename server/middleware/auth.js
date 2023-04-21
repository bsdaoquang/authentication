const jwt = require('jsonwebtoken')

const verifyToken = (req, res, next) => {
  const accessToken = req.headers.authorization

  const token = accessToken && accessToken.split(' ')[1]

  if (!token) return res.sendStatus(401)

  try {
    const verify = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)

    if (!verify) return res.sendStatus(403)

    next()
  } catch (error) {
    console.log(error)
    return res.sendStatus(403)
  }
}

module.exports = verifyToken
