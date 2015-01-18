# Peepmem

ruby module to peep memory of another process.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'peepmem'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install peepmem

## Example

    # Open process (pid = 3657)
    handle = Peepmem.open(3657) # => #<Peepmem::Handle: PID=3657>
    # Read memory at 0x00400000 as 16-byte string
    pointer = handle[0x00400000] # => #<Peepmem::Pointer:0x00000000400000 PID=3657>
    pointer['s16'] # => "\x7FELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    # Read as null-terminated string
    pointer['s'] # => "\x7FELF\x02\x01\x01"
    # Seek 16 bytes and read memory as 2-byte unsigned integer
    pointer += 16
    pointer['u2'] # => 2
    # Read as 2-byte unsigned integer, 4-byte unsigned integer and
    # 8-byte unsigned integer
    (pointer + 2)['u2 u4 u8'] # => [62, 1, 4209768]
    # Read memory at 0x00400018 as a pointer
    pointer = handle[0x00400018]['p'] # => #<Peepmem::Pointer:0x00000000403c68 PID=3657>>

## Supported Platforms

* Linux
* Windows

## Contributing

1. Fork it ( https://github.com/kubo/ruby-peepmem/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request
