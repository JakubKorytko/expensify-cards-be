const http = require('http');
const express = require('express');
const router = require('./router');
const bodyParser = require('body-parser')

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(bodyParser.urlencoded({
    extended: true
}));

app.use(router)
app.set('port', '3000');

const server = http.createServer(app);

server.listen('3000');
server.on('listening', () => console.log('Listening on port 3000'));
server.on('error', err => console.log(err));