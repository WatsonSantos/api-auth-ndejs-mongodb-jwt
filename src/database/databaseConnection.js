const mongoose = require('mongoose')
const localDataBase = process.env.localDataBase


function dataBaseConnection(){
    mongoose.connect(`mongodb://127.0.0.1/${localDataBase}`).then(() => {
        console.log("Conectado ao mongo")
    }).catch((erro) => {
        console.log("Erro ao se conectar ao mongo: " + erro)
    })
}


module.exports = dataBaseConnection;


