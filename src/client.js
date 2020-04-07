let express = require("express");

let app = express();

app.engine('pug', require('pug').__express)
app.set('view engine', 'pug');
app.set('views', '../public/client');

let access_token = null;
let refresh_token = null;
let scope = null;

app.get('/', function (req, res) {
  res.render('index', { access_token: access_token, refresh_token: refresh_token, scope: scope })
})

app.use('/', express.static('../public/client'));

let server = app.listen(9000, 'localhost', function () {
  let host = server.address().address;
  let port = server.address().port;
  console.log('OAuth Client is listening at http://%s:%s', host, port);
});
 
