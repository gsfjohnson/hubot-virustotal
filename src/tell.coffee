# Description:
#   Query virustotal for url reports.
#
# Dependencies:
#   virustotal.js
#   moment
#
# Configuration:
#   HUBOT_VIRUSTOTAL_API [required] - API KEY
#
# Notes:
#
# Author:
#   gfjohnson

moment = require 'moment'
virustotal = require 'virustotal.js'

if process.env.HUBOT_VIRUSTOTAL_API?
  virustotal.setKey(process.env.HUBOT_VIRUSTOTAL_API)


module.exports = (robot) ->

  robot.respond /virustotal url (.+)$/i, (msg) ->
    url = msg.match[1]

    virustotal.getUrlReport url, (err, res) ->
      return robot.send {room: name}, "#{err}" if err
      return robot.send {room: name}, "#{res}"

    return
