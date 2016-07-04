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

  robot.respond /virustotal url (.+)$/i, (msg) ->
    url = msg.match[1]

    virustotal.getUrlReport url, (err, res) ->
      return robot.send {room: msg.envelope.user.name}, "Virus total: `#{err.json.verbose_msg}`." if err

      clean = for scanner, obj of res.scans
        "`#{scanner}`" unless obj.detected

      unclean = for scanner, obj of res.scans
        "`#{scanner}` (#{obj.result})" if obj.detected

      return robot.send {room: msg.envelope.user.name}, "Virus total: #{res.resource} rated clean by #{clean.join ', '}.  Rated unclean by #{unclean.join ', '}."

    return
