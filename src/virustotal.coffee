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

maxRequestsPerInterval = 4
requestWindow = 1000
defaultwaitms = 1000

# send queue
sq = []

queueUrlReport = (robot, msg, url) ->
  ms = Date.now()
  sq.push { whenqueued: ms, sent: false, robot: robot, msg: msg, url: url }

servicequeue = ->
  ms = Date.now()
  cutoffms = ms - (requestWindow * maxRequestsPerInterval)

  # remove stale
  q = sq
  for o in q when o.whenqueued < cutoffms and o.sent
    sq.splice(sq.indexOf(o), 1)

  # count already sent objects, within the request window
  credit = maxRequestsPerInterval
  credit-- for o in sq when o.sent

  # send as many as we have credit for
  for o in sq when o.sent isnt true
    break if credit < 1
    getUrlReport o.robot, o.msg, o.url
    o.sent = true
    credit--

  # restart timer
  setTimeout servicequeue, defaultwaitms

getUrlReport = (robot, msg, url) ->
  virustotal.getUrlReport url, (err, res) ->
    if err
      msgout = "Virus total: error: `#{err.json.verbose_msg}`."
      robot.logger.info "#{msgout} [#{msg.envelope.user.name}]"
      return robot.send {room: msg.envelope.user.name}, msgout

    r = { clean: 0, unclean: 0 }
    for scanner, obj of res.scans
      r.clean++ unless obj.detected
      r.unclean++ if obj.detected

    msgout = "Virus total: `#{res.resource.replace('http:\/\/','')}` rated clean by #{r.clean}, unclean by #{r.unclean}.  More info: #{res.permalink}"
    robot.logger.info "#{msgout} [#{msg.envelope.user.name}]"
    return robot.send {room: msg.envelope.user.name}, msgout


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

    robot.logger.info "Virus total: url report request: #{url} [#{msg.envelope.user.name}]"

    virustotal.getUrlReport url, (err, res) ->
      if err
        msgout = "Virus total: error: `#{err.json.verbose_msg}`."
        robot.logger.info "#{msgout} [#{msg.envelope.user.name}]"
        return robot.send {room: msg.envelope.user.name}, msgout

      r = { clean: 0, unclean: 0 }
      for scanner, obj of res.scans
        r.clean++ unless obj.detected
        r.unclean++ if obj.detected

      msgout = "Virus total: `#{res.resource.replace('http:\/\/','')}` rated clean by #{r.clean}, unclean by #{r.unclean}.  More info: #{res.permalink}"
      robot.logger.info "#{msgout} [#{msg.envelope.user.name}]"
      return robot.send {room: msg.envelope.user.name}, msgout

    return
