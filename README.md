🚧 Source code under active development. 🚧

# guardian-express

It detects Linux Command, XSS, SQL Injection Text or sanitize them.

But it defense minimum amount and important things of mal-formed text.
Not completely defense all kinds of attacks.

This can be used in Express.js Router Middleware function.

```js
const guardian = require('./guardian-express')
app.all('/api*', (req, res, next) => {
  //validateRequest(req)
  next()
}, (req, res, next) => {
  console.log("Guardian Started.")
  //if(guardian.check.object(guardian.DETECT, req.headers)) return res.sendStatus(401) //Commenting bacause http://localhost:8080 keyword is in noraml state.
  if(common.has(req.body, ['tableName']))
    if(guardian.check.primitive(guardian.DETECT, req.body.tableName)) return res.sendStatus(401)
  if(common.has(req.body, ['row']))
    guardian.check.object(guardian.SANITIZE, req.body.row)
  if(common.has(req.body, ['option']))
  {
    if(guardian.check.object(guardian.DETECT, req.body.option)) return res.sendStatus(401)
    if(common.has(req.body.option, ['query']))
      if(guardian.check.object(guardian.DETECT, req.body.option.query)) return res.sendStatus(401)
  }
  console.log("Guardian Passed.")
  next()
})
})
```
