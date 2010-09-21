$FAIL = 0
$SUCCESS = 0

def expect_fail(object, errtype, errmsg, func, *args)
  begin
    object.send(func, *args)
  rescue errtype => e
    puts "OK: #{func} #{errmsg} threw #{errtype.to_s}"
    $SUCCESS = $SUCCESS + 1
  rescue => e
    puts "FAIL: #{func} #{errmsg} expected to throw #{errtype.to_s}, but instead threw #{e.class.to_s}: #{e.to_s}"
    $FAIL = $FAIL + 1
  else
    puts "FAIL: #{func} #{errmsg} expected to throw #{errtype.to_s}, but threw nothing"
    $FAIL = $FAIL + 1
  end
end

def expect_too_many_args(object, func, *args)
  expect_fail(object, ArgumentError, "too many args", func, *args)
end

def expect_too_few_args(object, func, *args)
  expect_fail(object, ArgumentError, "too few args", func, *args)
end

def expect_invalid_arg_type(object, func, *args)
  expect_fail(object, TypeError, "invalid arg type", func, *args)
end

def puts_ok(str)
  puts "OK: " + str
  $SUCCESS = $SUCCESS + 1
end

def puts_fail(str)
  puts "FAIL: " + str
  $FAIL = $FAIL + 1
end

def finish_tests
  puts "Successfully finished #{$SUCCESS} tests, failed #{$FAIL} tests"
end
