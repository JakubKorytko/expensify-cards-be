const http = require('http');
const express = require('express');
const cookieParser = require('cookie-parser');

const router = require('./router');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

app.use(router)
app.set('port', '3000');

const server = http.createServer(app);

server.listen('3000');
server.on('listening', () => console.log('Listening on port 3000'));