#!/usr/bin/env ruby

require 'socket'
require 'thread'
require 'cgi'

$botname = "shinybot"

def valid_utf8?( s )
  s =~ /^(([\x00-\x7f]|[\xc0-\xdf][\x80-\xbf]|[\xe0-\xef][\x80-\xbf]{2}|[\xf0-\xf7][\x80-\xbf]{3})*)(.*)$/m
  $3.empty?
end

def make_tinyurl(url)
  tinyurl = nil
  Kernel.open( "|-", "r" ) do |f|
    if f
      tinyurl = f.read
    else
      exec "curl", "-s", "http://tinyurl.com/api-create.php?url=#{CGI.escape(url)}"
    end
  end
  tinyurl
end

def whois_for_ip( ip_string )
  unless ip_string =~ /^\d+\.\d+\.\d+\.\d+$/
    return "Error: malformed IP address (BUG)"
  end
  results = `whois #{ip_string}`
  s = nil
  if results =~ /^inetnum:\s+(.*)$/
    s = "in range " + $1.dup
  end
  if results =~ /^netname:\s+(.*)$/
    s ? (s += ": " + $1.dup) : (s = $1.dup)
  end
  if results =~ /^descr:\s+(.*)$/
    s ? (s += ", " + $1.dup) : (s = $1.dup)
  end
  if results =~ /^country:\s+(.*)$/
    s ? (s += ", " + $1.dup) : (s = $1.dup)
  end
  return s ? s : "No information found by whois"
end

def gitweb_url_for_repo( object, lineno, repo )
  base_git_dir = '/srv/git/'
  base_gitweb_url = 'http://fiji.sc/cgi-bin/gitweb.cgi?p='

  git = 'git --git-dir=' + base_git_dir + repo
  file = ''
  action = `#{git} cat-file -t #{object} 2>/dev/null`.chomp
  if action.empty?
    files = `#{git} rev-parse --verify HEAD:#{object} 2>/dev/null`.chomp
    if files.empty?
      grep = 'grep "/' + object + '$" 2>/dev/null'
      files = `#{git} ls-tree -r --name-only HEAD | #{grep}`.chomp
      if files.empty? or files =~ /\n/
        return nil
      end
      file = ';f=' + files
      object = `#{git} rev-parse HEAD:#{files}`.chomp
    else
      file = ';f=' + object
      object = files
    end
    action = `#{git} cat-file -t #{object} 2>/dev/null`.chomp
  end
  if action == 'object'
    action = 'objectdiff'
  end
  tail = ';hb=' + `sed 's/^ref: //' < #{base_git_dir}#{repo}/HEAD`.chomp
  if lineno
    tail += '#l' + lineno.gsub(/^:/,'')
  end
  return base_gitweb_url + repo + ';a=' + action + file + ';h=' + object + tail
end

def gitweb_url( object, lineno )
  repos = %w[
    fiji.git ImageJA.git trakem2.git VIB.git mpicbg.git bio-formats/.git
  ]

  repos.each do |repo|
    url = gitweb_url_for_repo( object, lineno, repo )
    if url
      return url
    end
  end
  return nil
end

class IRCClient

  attr_accessor :host, :port, :password, :realname, :nick, :channel

  def initialize
    # @host = "rrt.sc3d.org"
    @port = "6667"
    @host = "irc.freenode.net"
    @password = ""
    @realname = "shinybot version 0.3"
    @nick = $botname
    @channel = "fiji-devel"
    @mutex = Mutex.new
    @last_ping = nil
    @last_pong = nil
    @finding_a_nick = false
  end

  def iso_time
    Time.now.gmtime.strftime "%Y%m%dT%H%M%S"
  end

  def date_string
    Time.now.gmtime.strftime( "%Y-%m-%d" )
  end

  def today_log_file_name
    "/var/lib/fiji-irc-logs/fiji-irc-log-#{date_string}"
  end

  def log_line( line )
    open( today_log_file_name, File::WRONLY | File::CREAT | File::APPEND, 0666 ) do |f|
      f.puts line
    end
  end

  def log_message( who, what )
    log_line sprintf( "%s: %s: %s", iso_time, who, what )
  end

  def log_action( who, what )
    log_line sprintf( "%s: %s* %s", iso_time, who, what )
  end

  def log_event( event )
    log_line sprintf( "%s: *: %s", iso_time, event )
  end

  def log_name_change( who, whom )
    log_line sprintf( "%s: %s# %s", iso_time, who, whom )
  end

  def log_no_topic( who )
    log_line sprintf( "%s: %s> No topic is set", iso_time, who )
  end

  def log_topic( who, what )
    log_line sprintf( "%s: %s> set the topic to: %s", iso_time, who, what )
  end

  def parse_prefix( prefix )
    if prefix =~ /^([^\!]+)\!([^@]+)\@(.*)/
      [ $1, $2, $3 ]
    else
      raise "Got malformed prefix (#{prefix})"
    end
  end

  def send( command, *parameters )
    @mutex.synchronize do
      message = command + " " + parameters.join( ' ' ) + "\r\n"
      log_event "==> " + message.chomp
      @socket.print message
    end
  end

  def send_message( recipient, message )
    send( "PRIVMSG", recipient, ":" + message )
  end

  def send_last_lines( recipient, lines )
    send_message recipient, "\"last\" is disabled for the moment..."
    return
    log_today_lines = open( today_log_file_name, "r" ) { |f| f.readlines }
    filtered_lines = Array.new
    log_today_lines.each do |line|
      if line =~ /^........T......: ([^\*>][^: ]*): (.*)$/
        nick, user, host = parse_prefix $1
        filtered_lines.push "<" + nick + "> " + $2
      end
    end

    filtered_lines[-lines..-1].each do |line|
      send_message recipient, line.chomp
      sleep 0.5
    end
  end

  def get_next_line

    line = @socket.gets
    return unless line

    line.chomp!

    prefix = nil
    command = nil

    log_event "<== " + line

    if line.gsub!( /^:(\S+)\s+(\S+)/, '' )
      prefix = $1
      command = $2
    elsif line.gsub!( /^([^:]\S*)/, '' )
      command = $1
    else
      raise "Couldn't parse message from the IRC server: #{line}"
    end

    # Now call a handler for that command:

    case command

    when "ERROR"
      if line =~ /^\s+:(.*)/
        raise $1
      end

    when "433" # Then try another nick
      if @finding_a_nick
        if @nicks_tried >= 3
          # Then just exit...
          @socket.close
        else
          @nick = @nick + "_"
          @nicks_tried += 1
          send( "NICK", @nick )
        end
      end

    when "KICK"
      # Just rejoin immediately...
      send( "JOIN", "#" + @channel )

    when "376" # That's the end of MOTD message...
      @finding_a_nick = false
      send( "JOIN", "#" + channel )

    when "JOIN"
      replynick, replyuser, replyhost = parse_prefix prefix
      if ((replyhost == "gimel.esc.cam.ac.uk") || (replyhost == "82-69-166-74.dsl.in-addr.zen.co.uk") || (replyhost == "global.panaceas.org") || (replyhost == "fiji.sc")) &&
          (replyuser =~ /^n=([a-f0-9]{8})$/)
        begin
          message = nil
          ip_encoded_in_username = $1.dup
          a = ip_encoded_in_username.split( /(..)/ )
          ip_string = [ a[1], a[3], a[5], a[7] ].collect { |e| Integer("0x"+e).to_s }.join('.')
          host_results = `host #{ip_string}`
          if $?.success?
            if host_results =~ /\s(\S+)\. *$/
              send_message( "#" + @channel, "CGI:IRC user #{replynick} is logged in from #{$1} (#{ip_string}) [" + whois_for_ip(ip_string) + "]" )
            end
          else
            send_message( "#" + @channel, "CGI:IRC user #{replynick} is logged in from #{ip_string} [" + whois_for_ip(ip_string) + "]" )
          end
        rescue
        end
      end

    when "331" # No topic is set...
      if line =~ /^\s+(\S+)\s+(\S+)\s:(.*)$/
        recipient = $1
        channel = $2
        topic = $3
        log_no_topic( prefix )
      end

    when "332" # There is a topic set...
      if line =~ /^\s+(\S+)\s+(\S+)\s+:(.*)$/
        recipient = $1
        channel = $2
        topic = $3
        log_topic( prefix, topic )
      end

    when "TOPIC"
      if line =~ /^\s+(\S+)\s+:(.*)$/
        channel = $1
        topic = $2
        replynick, replyuser, replyhost = parse_prefix prefix
        log_topic( replynick, topic )
      end

    when "NICK"
      if line =~ /^\s+:(.*)$/
        new_name = $1
        replynick, replyuser, replyhost = parse_prefix prefix
        log_name_change( replynick, new_name )
      end

    when "PRIVMSG"
      if line =~ /^\s+(\S+)\s+:(.*)/
        recipient = $1
        text = $2
        # log_event "  recipient: " + recipient
        # log_event "  text: " + text

        if recipient == nick
          replynick, replyuser, replyhost = parse_prefix prefix
          replyto = replynick
        elsif recipient =~ /^(\#.*)/
            replynick, replyuser, replyhost = parse_prefix prefix
            replyto = $1
        else
          raise "Unknown type of PRIVMSG, line was: #{line}"
        end

        if text =~ /^\x01ACTION (.*)\x01$/
          unless valid_utf8?( $1 )
            send( "PRIVMSG", replyto, ":" + "That isn't valid UTF-8." )
          end
        else
          unless valid_utf8?( text )
            send( "PRIVMSG", replyto, ":" + "That isn't valid UTF-8." )
          end
        end

        if text =~ /^([dD])(u+)de(s?)([\. \!\?1]*)$/
          reply = ($1 == "d") ? "s" : "S"
          reply += "e" * $2.length
          reply += "riousl"
          reply += $3.empty? ? "y" : "ies"
          reply += $4
          send( "PRIVMSG", replyto, ":" + reply )
          return
        end

        if text =~ /\b([0-9a-f]{40}|[._0-9A-Za-z][-._0-9\/A-Za-z]+\.(java|py|rb|sh|cxx|bsh|clj|h|js|lut|svg|txt|TXT))(:\d+)?\b/
          url = gitweb_url( $1, $3 )
          if url
            tinyurl = make_tinyurl url
            send( "PRIVMSG", replyto, ":#{$1}#{$3} in Gitweb: " + tinyurl )
          end
        end

        if text =~ /([bB]ug|[Ii]ssue)\s+(\d+)/
          bug_number = $2.to_i(10)
          url = "http://fiji.sc/cgi-bin/bugzilla/show_bug.cgi?id=#{bug_number}"
          send( "PRIVMSG", replyto, ":Bug number #{bug_number} can be found here: #{url}" )
        end

        message = nil

        if (recipient == nick) && (text =~ /(^\s*|\W|^\s*y)a+rr+($|\W)/i)
          send( "MODE", "#" + @channel, "+o", replynick )
          return
        end

        if text =~ /^\!?#{@nick}[,:]?\s+(.*)\s*$/
          message = $1
        elsif ! (recipient =~ /^#/)
          message = text
        end

        if message
          case message
          when /^help/i
            send( "PRIVMSG", replyto, ":" + "I'm logging messages for the archive at http://fiji.sc/cgi-bin/fiji-irc")
          when /^last\s*$/
            send_last_lines( replynick, 5 )
          when /^last ([0-9]+)$/
            send_last_lines( replynick, Integer($1) )
          when /^.*\?\s*$/
            send_message( replyto, "Sorry, I don't know." )
          when /^\s*(\S+)\s*$/
            send( "PRIVMSG", replyto, ":" + "I don't know how to \"#{message.gsub(/\s+.*/,'')}\"." )
          else
            send( "PRIVMSG", replynick, ":" + "Sorry, I didn't understand that.  Try \"help\"." )
          end
        elsif text =~ /^\x01ACTION (.*)\x01$/
          log_action( replynick, $1 )
        elsif recipient =~ /^(\#.*)/
            log_message( prefix, text )
        else
          # Ignore the message...
          log_event "Ignoring that one..."
        end

      else
        raise "Couldn't parse a PRIVMSG (#{line})"
      end

    when "513"
      # Seem to get this if you PONG with the wrong reply number...

    when "PING"
      if line =~ /^\s+:(\S+)/
        send( "PONG", ":" + $1 )
      end

    when "PONG"
      if line =~ /^\s+\S+\s+:(\S+)/
        begin
          @last_pong = Integer( $1 )
        rescue
          raise "We got an unexpected PONG"
        end
      end

    end

    # log_event "   prefix is: " + prefix.to_s
    # log_event "   command is: " + command.to_s
    # log_event "   line left: " + line

  end

  def mainloop

    sleep_before_connecting = 0

    loop do

      sleep sleep_before_connecting

      @last_ping = nil
      @last_pong = nil

      begin
        @socket = TCPSocket.new( host, port )
      rescue SignalException => e
        log_event "Got signal #{e} on connecting, shutting down."
        exit( -1 )
      rescue Errno::ECONNREFUSED
        log_event "Connection refused; we'll try again..."
        log_event "Trying again in one minute..."
        sleep_before_connecting = 120
        next
      rescue SocketError => e
        log_event "Connection refused with a SocketError: " + e
        log_event "Trying again in one minute..."
        sleep_before_connecting = 120
        next
      rescue => e
        log_event "An exception was caught when trying to connect: " + e
        log_event "The exception type was: " + e.class.to_s
        log_event "Trying again in two minutes..."
        sleep_before_connecting = 240
        next
      end

      send( "PASS", password ) unless password.empty?

      @finding_a_nick = true

      send( "NICK", nick )
      @nicks_tried = 1

      # send( "USER", nick, "localhost", host, ":" + realname )
      send( "USER", nick, 0, "*", ":" + realname )

      actually_quit = false
      @pingthread_stop = false
      @pingthread = Thread.new { pingthread }

      loop do

        begin
          get_next_line
        rescue SignalException => e
          log_event "Got signal #{e}, shutting down."
          @pingthread_stop = true
          @pingthread.join
          actually_quit = true
          break
        rescue Interrupt
          log_event "Caught an interrupt: exiting."
          @pingthread_stop = true
          @pingthread.join
          actually_quit = true
          break
        rescue SyntaxError, NameError => e
          raise
        rescue => e
          log_event "When getting next line, got: " + e.message
          log_event "Waiting for pingthread to end..."
          @pingthread_stop = true
          @pingthread.join
          log_event "Trying again in two minutes..."
          sleep_before_connecting = 120
          break
        end

      end

      begin
        @socket.close
      rescue Errno::ENOTCONN
        log_event "Ignoring ENOTCONN on closing socket"
      rescue => e
        log_event "Got an exception when closing the socket: " + e
      end

      break if actually_quit

    end

  end

  def pingthread

    interrupt_the_read = false

    close_socket = nil

    loop do

      sleep 60

      if @last_ping
        if @last_pong
          if @last_pong < @last_ping
            log_event "Didn't get a reply to the last PING"
            log_event "We'll reconnect..."
            close_socket = true
            break
          end
        else
          log_event "Got no reply to the first PING"
          log_event "We'll reconnect..."
          close_socket = true
          break
        end
      end

      if @pingthread_stop
        log_event "We've been asked to stop by the main thread"
        log_event "We'll reconnect..."
        break
      end

      @last_ping = Time.now.to_i
      send( "PING", "#{@last_ping}" )

      unless @finding_a_nick
        if @nick != $botname
          @nick = $botname
          send( "NICK",  @nick )
        end
      end

    end

    if close_socket
      log_event "Trying to close the socket"
      @socket.close
      log_event "Finished trying to close the socket"
    end

  end

end

client = IRCClient.new

client.mainloop
