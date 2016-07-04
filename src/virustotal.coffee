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
      "virustotal url <url> - get url report"
    ]

    for str in arr
      cmd = str.split " - "
      cmds.push "`#{cmd[0]}` - #{cmd[1]}"

    robot.send {room: msg.message?.user?.name}, cmds.join "\n"

  robot.respond /virustotal url (.+)$/i, (msg) ->
    url = msg.match[1]

    robot.logger.info "Virus total: requested url report for #{url} [#{msg.envelope.user.name}]"
    
    virustotal.getUrlReport url, (err, res) ->
      if err
        msgout = "Virus total: error: `#{err.json.verbose_msg}`."
        robot.logger.info "#{msgout} [#{msg.envelope.user.name}]"
        return robot.send {room: msg.envelope.user.name}, msgout

      clean = []
      for scanner, obj of res.scans
        clean.push "`#{scanner}`" unless obj.detected

      unclean = []
      for scanner, obj of res.scans
        unclean.push "`#{scanner}` (#{obj.result})" if obj.detected

      msgout = "Virus total: `#{res.resource.replace('http:\/\/','')}` rated clean by #{clean.length}.  Rated unclean by #{unclean.length}.  More information: #{res.permalink}"
      robot.logger.info "#{msgout} [#{msg.envelope.user.name}]"
      return robot.send {room: msg.envelope.user.name}, msgout

    return
