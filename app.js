require("dotenv").config();
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const express = require("express");
const app = express();

const dataBaseConnection = require("./src/database/databaseConnection");

//Config JSON response
app.use(express.json());

//Database Connection
dataBaseConnection();

//Models
const User = require("./src/models/User");

//Opne route - Public route
app.get("/", (req, res) => {
  res.status(200).json({ message: "Bem-vindo a nossa API" });
});

//Private Routes

app.get("/user/:id", checkToken, async (req, res) => {
  const id = req.params.id;

  //Check if user exist

  const user = await User.findById(id, "-password");
  //Faz o retiorno dos dados excluindo a password

  if (!user) {
    return res.status(404).json({ message: "Utilizador não encontrado." });
  }

  res.status(200).json({ user });
});

function checkToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  //O header vem assim "Bearer $287e887387833787"
  //Dividindo a string e pegando a segunda posoção do array
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Acesso negado!" });
  }

  try {
    const secret = process.env.SECRET;
    jwt.verify(token, secret);

    next();
  } catch (error) {
    res.status(400).json({ message: "Token inválido!" });
  }
}

//Register User
app.post("/auth/register", async (req, res) => {
  const { name, email, password, confirmpassword } = req.body;

  //Validation
  if (!name) {
    return res.status(422).json({ message: "O nome é obrigatório" });
  }
  if (!email) {
    return res.status(422).json({ message: "O email é obrigatório" });
  }
  if (!password) {
    return res.status(422).json({ message: "A senha é obrigatória" });
  }
  if (password !== confirmpassword) {
    return res.status(422).json({ message: "As senha se diferem." });
  }

  //Check if user exist

  const userExists = await User.findOne({ email: email });

  if (userExists) {
    return res
      .status(422)
      .json({ message: "Já existe um utilizador cadastrado com esse email." });
  }

  //Create password

  const salt = await bcrypt.genSalt(12); //Tamanho da senha = 12
  const passwordHash = await bcrypt.hash(password, salt);

  //Create user
  const user = new User({
    name,
    email,
    password: passwordHash,
  });

  try {
    await user.save();
    res.status(201).json({ message: "Utilizador criado com sucesso!", user });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Erro no servidor, tente mais tarde!" });
  }
});

//Login route

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email) {
    return res.status(422).json({ message: "O email é obrigatório" });
  }
  if (!password) {
    return res.status(422).json({ message: "A senha é obrigatória" });
  }

  //Checks if user exixts
  const user = await User.findOne({ email: email });

  if (!user) {
    return res.status(404).json({ message: "Utilizador não encontrado!" });
  }

  //Check if password match

  const checkPassword = await bcrypt.compare(password, user.password);

  if (!checkPassword) {
    return res.status(422).json({ message: "Senha inválida!" });
  }

  try {
    const secret = process.env.secret;
    const token = jwt.sign(
      {
        id: user._id,
      },
      secret
    );

    res
      .status(200)
      .json({ message: "Autenticação realizada com sucesso", token });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Erro no servidor, tente mais tarde!" });
  }
});

app.listen(8000);
