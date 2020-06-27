const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const emailValidator = require("email-validator");
const passwordValidator = require('password-validator');


const User = require('../models/User');

var schema = new passwordValidator(); 

schema
.is().min(8)  
.is().max(30) 
.has().uppercase()                             
.has().lowercase()                              
.has().digits()                              
.has().not().spaces();                          


//Création d'un utilisateur


exports.signup = (req, res, next) => {  
    if (!emailValidator.validate(req.body.email) || (!schema.validate(req.body.password))) {  
        
        res.status(401).json({ error: 'Merci de bien vouloir entrer une adresse email et un mot de passe valide (minimum 8 caractère avec au moins 1 Majuscule 1 chiffre et sans espace) !' });  
       
    } else if (emailValidator.validate(req.body.email) && (schema.validate(req.body.password))) {  
    bcrypt.hash(req.body.password, 10)  
        .then(hash => { 
            const user = new User({
                email: req.body.email,
                password: hash
            });
            user.save()  
                .then(() => res.status(201).json({ message: 'Utilisateur créé !'}))
                .catch(error => res.status(400).json({ error }));
        })
        .catch(error => res.status(500).json({ error }));
    }
};

//Connexion d'un utilisateur déjà inscrit
exports.login = (req, res, next) => {
    User.findOne({ email: req.body.email })
        .then(user => {
            if (!user) {
                return res.status(401).json({ error: 'Utilisateur non trouvé !' });
            }
            bcrypt.compare(req.body.password, user.password)
                .then(valid => {
                    if (!valid) {
                        return res.status(401).json({ error: 'Mot de passe incorrect !' });
                    }
                    res.status(201).json({
                        message: 'Connexion réussie!',
                        userId: user._id,
                        token: jwt.sign({ userId: user._id },
                            'RANDOM_TOKEN_SECRET', { expiresIn: '24h' }
                        )
                    });
                })
                .catch(error => res.status(500).json({ error }));
        })
        .catch(error => res.status(500).json({ error }));
};