const express = require('express');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const cors = require('cors')


// const corsOptions = {
//     origin: 'http://localhost:5173',
//     optionsSuccessStatus: 200
// }



class TokenBucket {

    constructor(capacity, fillPerSecond) {
        this.capacity = capacity;
        this.tokens = capacity;
        setInterval(() => this.addToken(), 1000 / fillPerSecond);
    }

    addToken() {
        if (this.tokens < this.capacity) {
            this.tokens += 1;
        }
    }

    take() {
        if (this.tokens > 0) {
            this.tokens -= 1;
            return true;
        }

        return false;
    }
}

const app = express();



app.use(express.json());
// app.use(cors())


dotenv.config();

let refreshTokenDB = [];
function limitRequests(perSecond, maxBurst) {
    const bucket = new TokenBucket(maxBurst, perSecond);

    // Return an Express middleware function
    return function limitRequestsMiddleware(req, res, next) {
        if (bucket.take()) {
            next();
        } else {
            res.status(429).send('Rate limit exceeded');
        }
    }
}

function verifyToken(req, res, next) {
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(403).send('Token jest wymagany.');
  }

  try {
    req.user = jwt.verify(token, process.env.TOKEN_SECRET);
  } catch (err) {
    return res.status(401).send('Nieważny token.');
  }

  return next();
}


app.post('/login', cors(), (req, res) => {

  const userInfo = {
    id: 2,
    name: 'Jarosław',
    surname: 'Tracz'
  }

  const token = jwt.sign({ userInfo }, process.env.TOKEN_SECRET, { expiresIn: '1h' });


  const refreshToken = jwt.sign(
      { userInfo },
      process.env.REFRESH_TOKEN_SECRET,
      { expiresIn: '7d' }
  );

    refreshTokenDB.push(refreshToken)

  res.json({ token, refreshToken });
});


app.get('/protected', verifyToken, (req, res) => {

    return res.json({
        message: 'Ty hakerze'
    })

})

app.get('/test',
    limitRequests(1, 5), // Apply rate limiting middleware
    (req, res) => {
        res.send('Hello from the rate limited API');
    }
);



app.delete('/logout', (req, res) => {

    const { refreshToken } = req.body;

    if (!refreshToken) {
        return res.status(404).send('Brak refresh token.');
    }

    if(!refreshTokenDB.includes(refreshToken)) return res.status(401).send('Błędny refresh token');

    refreshTokenDB = refreshTokenDB.filter(item => item !== refreshToken)


    return res.json({
        message: 'Zostałeś wylogowany'
    })

})


app.post('/refresh-token', (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(401).send('Refresh Token jest wymagany');
  }

  try {

      if(!refreshTokenDB.includes(refreshToken)) return res.status(401).send('Błędny refresh token');


    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);

    if(decoded){
        refreshTokenDB = refreshTokenDB.filter(item => item !== refreshToken)
    }


    const accessToken = jwt.sign(
        { userInfo: decoded.userInfo },
        process.env.TOKEN_SECRET,
        { expiresIn: '15m' }
    );

    const newRefreshToken = jwt.sign(
        { userInfo: decoded.userInfo },
        process.env.REFRESH_TOKEN_SECRET,
        { expiresIn: '7d' }
    );

      refreshTokenDB.push(newRefreshToken)

    res.json({ accessToken, newRefreshToken });
  } catch (error) {
    res.status(403).send('Nieprawidłowy Refresh Token');
  }
});


app.listen(3000, () => {
  console.log('Serwer działa na porcie 3000');
});
