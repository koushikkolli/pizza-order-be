const jwt = require("jsonwebtoken")

async function validateUser(req, res, next){
    try{
    let token = req.headers.authorization
    if (token != undefined){
        let decode = await jwt.verify(token, process.env.SECRET_KEY)
        if (decode){
            req.role = decode.role
            req.user = decode.userMail
            next()
        }
        else{
            res.status(401).json({
                message: "You are not authorized"
            })
        }

    }
    else{
        res.status(401).json({
            message: "You are not authorized"
        })
    }
    }
    catch(error){
        res.status(401).json({
            message: "You are not authorized"
        })
    }
    
}


function checkRole(role){
    return function(req, res, next){
        if (req.role === role){
            next()
        }
        else if (req.body.mail === req.user){
            next()
        }
        else{
            res.status(401).json({
                message:"You are authorized to do this request"
            })
        }
    }
}

module.exports={ validateUser, checkRole }