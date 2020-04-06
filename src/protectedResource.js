let express = require("express");
let cons = require('consolidate');
let bodyParser = require('body-parser');
let __ = require('underscore');
let cors = require('cors');

let app = express();

app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for bearer tokens)

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', '../html/protectedResource');
app.set('json spaces', 4);

app.use('/', express.static('../html/protectedResource'));
app.use(cors());

let resource = {
	"name": "Protected Resource",
	"description": "This data has been protected by OAuth 2.0"
};

let server = app.listen(9002, 'localhost', function () {
  let host = server.address().address;
  let port = server.address().port;

  console.log('OAuth Resource Server is listening at http://%s:%s', host, port);
});
 
