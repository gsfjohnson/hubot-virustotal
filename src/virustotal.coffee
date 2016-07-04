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

modulename = 'Virus total'
maxRequestsPerInterval = 4
requestWindowMs = 60 * 1000
defaultwaitms = 1000

# send queue
sq = []

queueUrlReport = (robot, msg, url) ->
  ms = Date.now()
  if sq.length >= maxRequestsPerInterval
    msgout = "#{modulename}: api max requests per interval reached. Your request will be serviced as soon as possible.  Window `#{sq.length}`."
    robot.logger.info "#{msgout} [#{msg.envelope.user.name}]"
    robot.send {room: msg.envelope.user.name}, msgout
  sq.push { whenqueued: ms, sent: false, robot: robot, msg: msg, url: url }
  # robot.logger.debug "sq: { whenqueued: #{ms}, url: #{url} }"

servicequeue = ->
  ms = Date.now()
  cutoffms = ms - requestWindowMs

  # remove stale
  removequeue = []
  for o in sq when o.whenqueued < cutoffms and o.sent
    # o.robot.logger.debug "servicequeue: queueing stale object for removal: { whenqueued: #{o.whenqueued}, url: #{o.url}, sent: #{o.sent} }"
    removequeue.push o

  while removequeue.length > 0
    o = removequeue.shift()
    # o.robot.logger.debug "servicequeue: purging stale object: { whenqueued: #{o.whenqueued}, url: #{o.url}, sent: #{o.sent} }"
    sq.splice(sq.indexOf(o), 1)

  # count already sent objects, within the request window
  credit = maxRequestsPerInterval
  credit-- for o in sq when o.sent

  # send as many as we have credit for
  for o in sq when o.sent isnt true
    # o.robot.logger.debug "servicequeue: credit check #{credit} before sending: { whenqueued: #{o.whenqueued}, url: #{o.url}, sent: #{o.sent} }"
    break if credit < 1
    getUrlReport o.robot, o.msg, o.url
    o.sent = true
    credit--

  # restart timer
  setTimeout servicequeue, defaultwaitms

getUrlReport = (robot, msg, url) ->
  # robot.logger.info "sq: sending virustotal request for #{url}"
  virustotal.getUrlReport url, (err, res) ->
    if err
      msgout = "#{modulename}: error: `#{err.json.verbose_msg}`."
      robot.logger.info "#{msgout} [#{msg.envelope.user.name}]"
      return robot.send {room: msg.envelope.user.name}, msgout

    r = { clean: 0, unclean: 0 }
    for scanner, obj of res.scans
      r.clean++ unless obj.detected
      r.unclean++ if obj.detected

    msgout = "#{modulename}: `#{res.resource.replace('http:\/\/','')}` rated clean by #{r.clean}, unclean by #{r.unclean}.  More info: #{res.permalink}"
    robot.logger.info "#{msgout} [#{msg.envelope.user.name}]"
    return robot.send {room: msg.envelope.user.name}, msgout


module.exports = (robot) ->

  unless process.env.HUBOT_VIRUSTOTAL_API?
    robot.logger.warning "#{modulename}: environment variable HUBOT_VIRUSTOTAL_API not set."
  else
    virustotal.setKey(process.env.HUBOT_VIRUSTOTAL_API)

  setTimeout servicequeue, defaultwaitms

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

    robot.logger.info "#{modulename}: url report request: #{url} [#{msg.envelope.user.name}]"

    return queueUrlReport robot, msg, url
