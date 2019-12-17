import express from 'express'
import bodyParser from 'body-parser'
import cors from 'cors'
import bcryptjs from 'bcryptjs'
import mongoose from 'mongoose'
import escapeHtml from 'escape-html'
import jwt from 'jsonwebtoken'
import dotenv from 'dotenv'
mongoose.connect('mongodb://127.0.0.1:27017/kikou', {useCreateIndex: true,useNewUrlParser: true});
dotenv.config()

//console.log(process.env.SECRET)

const db = mongoose.connection;
db.on('error', console.error);
db.once('open', function() {
})

const userSchema = new mongoose.Schema({
    name: String,
    email: {
        unique: true,
        type: String
    },
    password: String
})

const user = mongoose.model('user', userSchema)

const app = express()

app.use(cors({
    origon: '*'
}))
app.use(bodyParser.json())
app.use(express.static('docs'))


function verifyToken(req, res, next) {
    let token = req.headers.authorization
    if (typeof token === 'string' && token.startsWith('Bearer')){
        token = token.substring(7)
        try {
            jwt.verify(token, process.env.SECRET)
            return next()
        } catch (e) {
            res.status(401)
            res.json({
                error: "denied token"
            })
        }
    }else {
        res.status(401)
        res.json({
            error: "denied token"
        })
    }
}

/**
 * @api {post} /login Se connecter
 * @apiName PostLogin
 * @apiGroup Users
 * @apiHeader Content-Type=application/json application/json
 * @apiExample Example usage:
 *     body:
 *     {
 *       "email": "user@email.com",
 *       "password": "szjkdjklkjdz"
 *     }
 * @apiParam (body/json) {String} email User email
 * @apiParam (body/json) {String} password User password
 * @apiSampleRequest login
 */

app.get('/me', verifyToken, (req, res)=>{
    const token = req.headers.authorization.substring(7)
    const decoded = jwt.verify(token, process.env.SECRET)
    res.json({
        id: decoded.id,
        email: decoded.email,
        name: decoded.name
    })
})

/**
 * @api {post} /user Créer un utilisateur
 * @apiName PostUser
 * @apiGroup Users
 * @apiHeader Content-Type=application/json application/json
 * @apiExample Example usage:
 *     body:
 *     {
 *       "email": "user@email.com",
 *       "name": "User name",
 *       "password": "szjkdjklkjdz"
 *     }
 * @apiParam (body/json) {String} email User email
 * @apiParam (body/json) {String} name User name
 * @apiParam (body/json) {String} password User password
 * @apiSampleRequest user
 */

app.post('/user', async (req, res)=>{
    const email = escapeHtml(req.body.email)
    const password = escapeHtml(req.body.password)
    const name = escapeHtml(req.body.name)

    const hash = bcryptjs.hashSync(password, 8)

    const reponse = new user({
        name, //<-- racourcie de name: name,
        email, //<-- racourcie de email: email,
        password: hash, //<-- racourcie de password: password
    }).save(console.log)

    try {
        const data = (await reponse.save()).toObject()
        delete data.password
        res.json(data)
    } 
    catch (e) {
        res.status(401)
        res.json({
            error: e.errmsg
        })
    }
})

app.post('/login', async (req, res) => {
    const email = req.body.email
    const password = req.body.password
    
    const data = await user.findOne({
        email
    })
    if (bcryptjs.compareSync(password, data.password)) {
        const token = jwt.sign({
            id: data._id,
            name: data.name,
            email: data.email
        }, process.env.SECRET, {
            expiresIn: 86400
        })
        res.json({
            token
        })
    }
    else {
        res.status(401)
        res.json({
            error: "identifiant invalid"
        })
    }
})

app.get('*', (req, res)=> {
    res.status(500)
    res.send('denied')
})

app.listen(3000, ()=> {
    console.log('http://localhost:3000')
})