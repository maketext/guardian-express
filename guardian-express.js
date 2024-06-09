const _ = require("lodash")
const blackList = {
  command: ['sudo ', 'mv ', 'cp ', './'],
  xss: ['setTimeout', 'setInterval', 'eval('],
  sql: ['1=1', 'drop '],
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
  sanitizeInjection: function (type, str) {
    if(typeof str === 'string')
    {
      for(let blackWord of blackList[type])
        str = str.replace(new RegExp(`${blackWord}`, "gi"), '')
      if(type === 'xss')
        str = sanitizeURL(str)
      else if(type === 'sql')
      {
        // countSqlInjectionPattern 에 의한 세니타이징 코드 추가 필요.
      }
    }
    return str
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
            return true
      }
  if(cmd === 'sanitize') return obj
  else if(cmd === 'detect') return false
}
function checkArray(cmd, arr) {
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
            return true
      }
  if(cmd === 'sanitize') return arr
  else if(cmd === 'detect') return false
}

const wholeObject = {
  DETECT: 'detect', // for symbol text
  SANITIZE: 'sanitize', // for symbol text
  ...method,
  check: {
    object: checkObject,
    array: checkArray
  }
}

module.exports = wholeObject