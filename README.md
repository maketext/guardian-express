"🚧 Source code under active development. 🚧

# guardian-express

It detects Linux Command, XSS, SQL Injection Text or sanitize them.

But it defense minimum amount and important things of mal-formed text.
Not completely defense all kinds of attacks.

This can be used in Express.js Router Middleware function.

```js
const guardian = require('./guardian-express')
app.use((req, res, next) => {
	//res.locals.flash = []
	
	if(
		guardian.check.object(sec.DETECT, req.headers) ||
		guardian.check.object(sec.DETECT, req.body)
		)
		return res.sendStatus(401)
	else
	{
		if(_.has(req.body, 'row'))
			if(guardian.check.object(sec.DETECT, req.body.row))
				return res.sendStatus(401)
		if(_.has(req.body, 'tableName'))
			if(guardian.detectInjectionAll(req.body.tableName))
				return res.sendStatus(401)
		if(_.has(req.body, 'document'))
			if(guardian.check.object(sec.DETECT, req.body.document))
				return res.sendStatus(401)
	}
})
```
