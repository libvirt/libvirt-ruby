# this program demonstrates the use of the libvirt event APIs.  This example
# is very, very complicated because:
# 1) the libvirt event APIs are complicated and
# 2) it tries to simulate a multi-threaded UI program, leading to some weirdness

require 'libvirt'

class VirEventLoop
  class VirEventLoopHandle
    # represents an event handle (usually a file descriptor).  When an event
    # happens to the handle, we dispatch the event to libvirt via
    # Libvirt::event_invoke_handle_callback (feeding it the handleID we returned
    # from add_handle, the file descriptor, the new events, and the opaque
    # data that libvirt gave us earlier)
    attr_accessor :handleID, :fd, :events
    attr_reader :opaque

    def initialize(handleID, fd, events, opaque)
      puts "PROG: VirEventLoopHandle.initialize"
      @handleID = handleID
      @fd = fd
      @events = events
      @opaque = opaque
    end

    def dispatch(events)
      puts "PROG: handle dispatch called with events #{events}"
      Libvirt::event_invoke_handle_callback(@handleID, @fd, events, @opaque)
    end
  end

  class VirEventLoopTimer
    # represents a timer.  When a timer expires, we dispatch the event to
    # libvirt via Libvirt::event_invoke_timeout_callback (feeding it the timerID
    # we returned from add_timer and the opaque data that libvirt gave us
    # earlier)
    attr_accessor :lastfired, :interval
    attr_reader :timerID, :opaque

    def initialize(timerID, interval, opaque)
      puts "PROG: VirEventLoopTimer.initialize"
      @timerID = timerID
      @interval = interval
      @opaque = opaque
      @lastfired = 0
    end

    def dispatch
      puts "PROG: timer dispatch"
      Libvirt::event_invoke_timeout_callback(@timerID, @opaque)
    end
  end

  def initialize
    puts "PROG: VirEventLoop.initialize"
    @nextHandleID = 1
    @nextTimerID = 1
    @handles = []
    # a bit of oddness having to do with signalling.  Since signals are
    # unreliable in a multi-threaded program, create a "self-pipe".  The read
    # end of the pipe will be part of the pollin array, and will be selected
    # on during "run_once".  The write end of the pipe is available to the
    # callbacks registered with libvirt.  When libvirt does an add, update,
    # or remove of either a handle or a timer, the callbacks will write a single
    # byte (via the interrupt method) to the write end of the pipe.  This will
    # cause the select loop in "run_once" to wakeup and recalculate the
    # polling arrays and timers based on the new information.
    @rdpipe, @wrpipe = IO.pipe
    @pending_wakeup = false
    @running_poll = false
    @quit = false

    @timers = []

    @pollin = []
    @pollout = []
    @pollerr = []
    @pollhup = []

    @pollin << @rdpipe
  end

  def next_timeout
    # calculate the smallest timeout of all of the registered timeouts
    nexttimer = 0
    @timers.each do |t|
      puts "PROG: next_timeout, timer #{t.timerID} last #{t.lastfired} interval #{t.interval}"
      if t.interval < 0
        next
      end
      if nexttimer == 0 or (t.lastfired + t.interval) < nexttimer
        nexttimer = t.lastfired + t.interval
      end
    end

    return nexttimer
  end

  def print_pollers
    # debug function to print the polling arrays
    print "PROG: pollin: ["
    @pollin.each{|x| print "#{x.fileno}, "}
    puts "]"
    print "PROG: pollout: ["
    @pollin.each{|x| print "#{x.fileno}, "}
    puts "]"
    print "PROG: pollerr: ["
    @pollin.each{|x| print "#{x.fileno}, "}
    puts "]"
  end

  def run_once
    # the main loop of the program.  This loop first calculates the smallest
    # timeout value (via next_timeout).  Based on that, it knows how long to
    # sleep for in the select (it sleeps forever if there are no timers
    # registered).  It then does a select on all of the registered file
    # descriptors, waking up if one of them becomes active or we hit the
    # timeout.  If one of the file descriptors becomes active, we properly
    # dispatch the handle event to libvirt.  If we woke up because of a timeout
    # we dispatch the timeout callback to libvirt.
    puts "PROG: VirEventLoop.run_once"

    sleep = -1
    @running_poll = true
    nexttimer = next_timeout
    puts "PROG: Next timeout at #{nexttimer}"

    if nexttimer > 0
      now = Time.now.to_i * 1000
      if now >= nexttimer
        sleep = 0
      else
        sleep = (nexttimer - now) / 1000.0
      end
    end

    if sleep < 0
      events = IO.select(@pollin, @pollout, @pollerr)
    else
      events = IO.select(@pollin, @pollout, @pollerr, sleep)
    end

    print_pollers

    if not events.nil?
      puts "PROG: after poll, 0 #{events[0]}, 1 #{events[1]}, 2 #{events[2]}"
      (events[0] + events[1] + events[2]).each do |io|
        if io.fileno == @rdpipe.fileno
          @pending_wakeup = false
          pipe = @rdpipe.read(1)
          next
        end

        @handles.each do |handle|
          if handle.fd == io.fileno
            libvirt_events = 0
            if events[0].include?(io)
              libvirt_events |= Libvirt::EVENT_HANDLE_READABLE
            elsif events[1].include?(io)
              libvirt_events |= Libvirt::EVENT_HANDLE_WRITABLE
            elsif events[2].include?(io)
              libvirt_events |= Libvirt::EVENT_HANDLE_ERROR
            end
            handle.dispatch(libvirt_events)
          end
        end
      end
    end

    now = Time.now.to_i * 1000
    @timers.each do |t|
      if t.interval < 0
        next
      end

      want = t.lastfired + t.interval
      if now >= (want - 20)
        t.lastfired = now
        t.dispatch
      end
    end

    @running_poll = false
  end

  def run_loop
    # run "run_once" forever
    puts "PROG: VirEventLoop.run_loop"
    while true
      run_once
    end
  end

  def interrupt
    # write a byte to the internal pipe to wake up "run_once" for recalculation.
    # See initialize for more information about the internal pipe
    puts "PROG: VirEventLoop.interrupt"
    if @running_poll and not @pending_wakeup
      @pending_wakeup = true
      @wrpipe.write('c')
    end
  end

  def register_fd(fd, events)
    # given an fd and a set of libvirt events, register the fd in the
    # appropriate polling arrays.  These arrays are used in "run_once" to
    # determine what to poll on
    puts "PROG: register fd #{fd} for events #{events}"
    if (events & Libvirt::EVENT_HANDLE_READABLE) != 0
      @pollin << IO.new(fd, 'r')
    end
    if (events & Libvirt::EVENT_HANDLE_WRITABLE) != 0
      @pollout << IO.new(fd, 'w')
    end
    if (events & Libvirt::EVENT_HANDLE_ERROR) != 0
      @pollerr << IO.new(fd, 'r')
    end
    if (events & Libvirt::EVENT_HANDLE_HANGUP) != 0
      @pollhup << IO.new(fd, 'r')
    end
  end

  def unregister_fd(fd)
    # remove an fd from all of the poll arrays.  run_once will no longer select
    # on this fd
    @pollin.delete_if {|x| x.fileno == fd}
    @pollout.delete_if {|x| x.fileno == fd}
    @pollerr.delete_if {|x| x.fileno == fd}
    @pollhup.delete_if {|x| x.fileno == fd}
  end

  def add_handle(fd, events, opaque)
    # add a handle to be tracked by this object.  The application is
    # expected to maintain a list of internal handle IDs (integers); this
    # callback *must* return the current handleID.  This handleID is used
    # both by libvirt to identify the handle (during an update or remove
    # callback), and is also passed by the application into libvirt when
    # dispatching an event.  The application *must* also store the opaque
    # data given by libvirt, and return it back to libvirt later
    # (see remove_handle)
    puts "PROG: VirEventLoop.add_handle"
    handleID = @nextHandleID + 1
    @nextHandleID = handleID

    @handles << VirEventLoop::VirEventLoopHandle.new(handleID, fd, events,
                                                     opaque)

    register_fd(fd, events)

    interrupt

    return handleID
  end

  def update_handle(handleID, events)
    # update a previously registered handle.  Libvirt tells us the handleID
    # (which was returned to libvirt via add_handle), and the new events.  It
    # is our responsibility to find the correct handle and update the events
    # it cares about
    puts "PROG: VirEventLoop.update_handle handleID #{handleID}, events #{events}"
    @handles.each do |handle|
      if handle.handleID == handleID
        puts "PROG: updating handle #{handleID} with fd #{handle.fd}"
        handle.events = events
        unregister_fd(handle.fd)
        register_fd(handle.fd, events)
        interrupt
      end
    end
  end

  def remove_handle(handleID)
    # remove a previously registered handle.  Libvirt tells us the handleID
    # (which was returned to libvirt via add_handle), and it is our
    # responsibility to "forget" the handle.  We must return the opaque data
    # that libvirt handed us in "add_handle", otherwise we will leak memory
    puts "PROG: VirEventLoop.remove_handle"
    handles = []
    @handles.each do |h|
      if h.handleID == handleID
        unregister_fd(h.fd)
        puts "PROG: Removed handle #{handleID} fd #{h.fd}"
        opaque = h.opaque
      else
        handles << h
      end
    end
    @handles = handles
    interrupt

    return opaque
  end

  def add_timer(interval, opaque)
    # add a timeout to be tracked by this object.  The application is
    # expected to maintain a list of internal timer IDs (integers); this
    # callback *must* return the current timerID.  This timerID is used
    # both by libvirt to identify the timeout (during an update or remove
    # callback), and is also passed by the application into libvirt when
    # dispatching an event.  The application *must* also store the opaque
    # data given by libvirt, and return it back to libvirt later
    # (see remove_timer)
    puts "PROG: VirEventLoop.add_timer"
    timerID = @nextTimerID + 1
    @nextTimerID = timerID

    @timers << VirEventLoop::VirEventLoopTimer.new(timerID, interval, opaque)

    interrupt

    return timerID
  end

  def update_timer(timerID, interval)
    # update a previously registered timer.  Libvirt tells us the timerID
    # (which was returned to libvirt via add_timer), and the new interval.  It
    # is our responsibility to find the correct timer and update the timers
    # it cares about
    puts "PROG: VirEventLoop.update_timer ID #{timerID} interval #{interval}"
    @timers.each do |timer|
      if timer.timerID == timerID
        puts "PROG: updating timer"
        timer.interval = interval
        interrupt
      end
    end
  end

  def remove_timer(timerID)
    # remove a previously registered timeout.  Libvirt tells us the timerID
    # (which was returned to libvirt via add_timer), and it is our
    # responsibility to "forget" the timer.  We must return the opaque data
    # that libvirt handed us in "add_timer", otherwise we will leak memory
    puts "PROG: VirEventLoop.remove_timer"
    timers = []
    @timers.each do |t|
      if t.timerId == timerID
        opaque = t.opaque
      else
        timers << t
        puts "PROG: Remove timer #{timerID}"
      end
    end
    @timers = timers
    interrupt
    return opaque
  end
end

# allocate a global VirEventLoop object.  This needs to be global because it
# will be referenced in each of the event impl callbacks
$eventLoop = VirEventLoop.new

$virEventAddHandleImpl = lambda {|fd, events, opaque|
  puts "PROG: virEventAddHandleImpl"
  return $eventLoop.add_handle(fd, events, opaque)
}

def virEventUpdateHandleImpl(watch, event)
  puts "PROG: virEventUpdateHandleImpl"
  return $eventLoop.update_handle(watch, event)
end

def virEventRemoveHandleImpl(handleID)
  puts "PROG: virEventRemoveHandleImpl"
  return $eventLoop.remove_handle(handleID)
end

def virEventAddTimerImpl(interval, opaque)
  puts "PROG: virEventAddTimerImpl"
  return $eventLoop.add_timer(interval, opaque)
end

def virEventUpdateTimerImpl(timer, timeout)
  puts "PROG: virEventUpdateTimerImpl"
  return $eventLoop.update_timer(timer, timeout)
end

def virEventRemoveTimerImpl(timerID)
  puts "PROG: virEventRemoveTimerImpl"
  return $eventLoop.remove_timer(timerID)
end

def virEventLoopStart
  puts "PROG: event loop start"

  # register the handle implementations with libvirt.  Each callback is
  # either a Symbol to a function or a Proc.
  Libvirt::event_register_impl($virEventAddHandleImpl,
                               :virEventUpdateHandleImpl,
                               :virEventRemoveHandleImpl,
                               :virEventAddTimerImpl,
                               :virEventUpdateTimerImpl,
                               :virEventRemoveTimerImpl)

  Thread.new {
    # continuously run the loop looking to dispatch callbacks
    $eventLoop.run_loop()
  }
end

# the domain callbacks that will be registered below.  Note that each type of
# domain callback (lifecycle, reboot, etc) need to accept a certain number
# of parameters; see the ruby-libvirt API documentation for a full list
dom_event_callback1 = lambda {|conn, dom, event, detail, opaque|
  puts "PROG: dom_event_callback1: conn #{conn}, dom #{dom}, event #{event}, detail #{detail}, opaque #{opaque}"
}

def dom_event_callback_lifecycle(conn, dom, event, detail, opaque)
  puts "PROG: dom_event_callback_lifecycle: conn #{conn}, dom #{dom}, event #{event}, detail #{detail}, opaque #{opaque}"
end

def dom_event_callback_reboot(conn, dom, opaque)
  puts "PROG: dom_event_callback_reboot: conn #{conn}, dom #{dom}, opaque #{opaque}"
end

# start the main program

# make sure to abort the program if any of the threads throw an exception
Thread.abort_on_exception = true

# if run with no arguments, connect to the qemu libvirt driver.  Otherwise try
# to connect to the given libvirt URI.
if ARGV.length == 0
  uri = "qemu:///system"
else
  uri = ARGV[0]
end

puts "Using uri: " + uri

# start up the event loop that will dispatch incoming events
virEventLoopStart

# connect to libvirt
conn = Libvirt::open(uri)

puts "PROG: Registering callbacks 1 and 2"
# register a callback for domain events using the old-style
# "domain_event_register".  The first parameter is the callback (either a
# Symbol to a function or a Proc), the second (optional) parameter is user
# supplied data to pass to the callback (this can be any valid ruby object).
# Note that domain_event_register is limited to "domain" events, and is
# deprecated in favor of domain_event_register_any
conn.domain_event_register(dom_event_callback1, ["hello", "there"])

# register a callback for domain events using the new-style
# "domain_event_register_any".  The first required parameter is which type of
# events to register for, and the second required parameters is the callback
# (either a Symbol to a function or a Proc).  The third (optional) parameter
# is which domain to get events for; if nil, events for all domains will be
# sent.  The fourth (optional) parameter is user supplied data to pass to the
# callback (this can be any valid ruby object).  The return value from
# domain_event_register_any *must* be stored by the application; this is the
# handle used to "unregister" this callback later.
cb2 = conn.domain_event_register_any(Libvirt::Connect::DOMAIN_EVENT_ID_LIFECYCLE,
                                     :dom_event_callback_lifecycle, nil,
                                     "sweet")

cb3 = conn.domain_event_register_any(Libvirt::Connect::DOMAIN_EVENT_ID_REBOOT,
                                     :dom_event_callback_reboot)

sleep 30

# after 30 seconds, unregister a couple of the callbacks to show how

puts "PROG: Deregistering callback 1"
conn.domain_event_deregister

puts "PROG: Deregistering reboot callback"
# deregister the reboot callback by passing the handle stored by
# domain_event_register_any
conn.domain_event_deregister_any(cb3)

while true
  sleep 1
end
