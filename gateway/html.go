package gateway

var (
	topHTML = `
<html>
  <head>
  </head>
  <body>
    <a href="{{.Url}}"> Sign in </a><br>
  </body>
</html>
`
	resourceHTML = `
<html>
  <head>
  </head>
  <body>
    <h3>Name : {{.Name}}</h3>
    <h3>Email : {{.Email}}</h3>
  </body>
</html>
`
)
