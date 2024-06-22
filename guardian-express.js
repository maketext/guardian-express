const _ = require("lodash")
const createDOMPurify = require('dompurify')
const { JSDOM } = require('jsdom')

const blackList = {
  command: ['sudo ', 'mv ', 'cp ', '\\.\\/'],
  xss: ['setTimeout', 'setInterval', 'eval\\('],
  sql: ['1\\=1', 'drop '],
}
const blackListTypes = ['command', 'xss', 'sql']


function detectURL(str) {
  return /http\:\/\//gi.exec(str) !== null || /https\:\/\//gi.exec(str) !== null
}
function sanitizeURL(str) {
  str = str.replace(/http\:\/\//gi, '[링크]http://')
  return str.replace(/https\:\/\//gi, '[링크]https://')
}

function countSqlInjectionPattern(input) {
  // 숫자=숫자 패턴을 찾는 정규표현식
  const pattern = /\b(\d+)=(\1)\b/g;
  const matches = input.match(pattern);
  return matches ? matches.length : 0;
}

const method = {
  detectInjection: function (type, str) {
    if(typeof str === 'string')
    {
      for(let blackWord of blackList[type])
        if(str.includes(blackWord))
          return true

      // Last Comparison
      if(type === 'xss')
        return detectURL(str)
      else if(type === 'sql')
        return countSqlInjectionPattern(str) > 0
    }
    return false
  },
  sanitizeInjection: function (type, plainText) {
    let securedText
    if(typeof plainText === 'string')
    {
      securedText = plainText
      console.log(plainText)
      for(let blackWord of blackList[type])
      {
        if(!securedText)
          securedText = plainText.replace(new RegExp(`${blackWord}`, "gi"), '')
        else
          securedText = securedText.replace(new RegExp(`${blackWord}`, "gi"), '')
      }
      if(type === 'xss')
      {
        securedText = sanitizeURL(securedText)
        if(securedText.length === plainText.length)
        {
          // When Guardian cannot sanitize, will try with DOMPurify.
          console.log("DOMPurify trying...")
          let window = new JSDOM('').window
          let DOMPurify = createDOMPurify(window)
          securedText = DOMPurify.sanitize(securedText)
        }
      }
      else if(type === 'sql')
      {
        // countSqlInjectionPattern 에 의한 세니타이징 코드 추가 필요.
      }
    }
    return securedText
  }
}
method.detectInjectionAll = function (str) {
  for(let type of blackListTypes)
    if(method.detectInjection(type, str)) return true
  return false
}
method.sanitizeInjectionAll = function (str) {
  for(let type of blackListTypes)
    str = method.sanitizeInjection(type, str)
  return str
}
function checkObject(cmd, obj) {
  flag = false
  if(cmd !== 'detect' && cmd !== 'sanitize') return true
  if(!_.isObject(obj)) return false
  for(let key in obj)
    if(typeof obj[key] === 'string')
      for(let type of blackListTypes)
      {
        if(cmd === 'sanitize')
          obj[key] = method.sanitizeInjection(type, obj[key])
        else if(cmd === 'detect')
          if(method.detectInjection(type, obj[key]))
            flag = true
      }
  if(cmd === 'sanitize') return obj
  else if(cmd === 'detect') return flag
}
function checkArray(cmd, arr) {
  let flag = false
  if(cmd !== 'detect' && cmd !== 'sanitize') return true
  if(Array.isArray(arr)) return false
  for(let [index, element] of arr.entries())
    if(typeof element === 'string')
      for(let type of blackListTypes)
      {
        if(cmd === 'sanitize')
          arr[index] = method.sanitizeInjection(type, element)
        else if(cmd === 'detect')
          if(method.detectInjection(type, element))
            flag = true
      }
  if(cmd === 'sanitize') return arr
  else if(cmd === 'detect') return flag
}
function checkPrimitive(cmd, value) {
  let flag = false
  if(cmd !== 'detect' && cmd !== 'sanitize') return true
  if(typeof element === 'string')
    for(let type of blackListTypes)
      {
        if(cmd === 'sanitize')
          value = method.sanitizeInjection(type, value)
        else if(cmd === 'detect')
          if(method.detectInjection(type, value))
            flag = true
      }
  if(cmd === 'sanitize') return value
  else if(cmd === 'detect') return flag
}

const wholeObject = {
  DETECT: 'detect', // for symbol text
  SANITIZE: 'sanitize', // for symbol text
  ...method,
  check: {
    primitive: checkPrimitive,
    object: checkObject,
    array: checkArray
  }
}

module.exports = wholeObject
