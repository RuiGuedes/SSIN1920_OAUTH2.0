let express = require("express");
let bodyParser = require('body-parser');
let __ = require('underscore');
let cors = require('cors');

let app = express();

app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for bearer tokens)

app.engine('pug', require('pug').__express)
app.set('view engine', 'pug');
app.set('views', '../public/protectedResource');
app.set('json spaces', 4);

app.use('/', express.static('../public/protectedResource'));
app.use(cors());

let resource = {
	"name": "Protected Resource",
	"description": "This data has been protected by OAuth 2.0"
};

app.get('/', function(req, res) {
	res.render('index', {});
});

let server = app.listen(9002, 'localhost', function () {
  let host = server.address().address;
  let port = server.address().port;

  console.log('OAuth Resource Server is listening at http://%s:%s', host, port);
});
 
