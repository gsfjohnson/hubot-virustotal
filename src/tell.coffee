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
# Commands:
#   hubot virustotal help - virustotal commands
#
# Notes:
#
# Author:
#   gfjohnson

moment = require 'moment'
virustotal = require 'virustotal.js'

module.exports = (robot) ->

  unless process.env.HUBOT_VIRUSTOTAL_API?
    robot.logger.warning 'The HUBOT_VIRUSTOTAL_API environment variable not set'
  else
    virustotal.setKey(process.env.HUBOT_VIRUSTOTAL_API)

  robot.respond /virustotal help$/, (msg) ->
    cmds = []
    arr = [
      "auth url <url> - get url report"
    ]

    for str in arr
      cmd = str.split " - "
      cmds.push "`#{cmd[0]}` - #{cmd[1]}"

    if replyInPrivate and msg.message?.user?.name?
      msg.reply 'replied to you in private!'
      robot.send {room: msg.message?.user?.name}, cmds.join "\n"
    else
      msg.reply cmds.join "\n"

  robot.respond /virustotal url (.+)$/i, (msg) ->
    url = msg.match[1]

    virustotal.getUrlReport url, (err, res) ->
      return robot.send {room: msg.envelope.user.name}, "Virus total: `#{err.json.verbose_msg}`." if err

      clean = []
      for scanner, obj of res.scans
        clean.push "`#{scanner}`" unless obj.detected
      clean.push "none" unless clean.length > 0

      unclean = []
      for scanner, obj of res.scans
        unclean.push "`#{scanner}` (#{obj.result})" if obj.detected
      unclean.push "none" unless unclean.length > 0

      return robot.send {room: msg.envelope.user.name}, "Virus total: `#{res.resource.replace('http:\/\/','')}` rated clean by #{clean.length}.  Rated unclean by #{unclean.length}.  More information at #{res.permalink}"

    return
